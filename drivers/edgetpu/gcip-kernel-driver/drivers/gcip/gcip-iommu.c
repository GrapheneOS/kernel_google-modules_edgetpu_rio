// SPDX-License-Identifier: GPL-2.0-only
/*
 * Manages GCIP IOMMU domains and allocates/maps IOVAs.
 *
 * Copyright (C) 2023 Google LLC
 */

#include <linux/bitops.h>
#include <linux/device.h>
#include <linux/dma-buf.h>
#include <linux/dma-direction.h>
#include <linux/dma-mapping.h>
#include <linux/genalloc.h>
#include <linux/iova.h>
#include <linux/limits.h>
#include <linux/log2.h>
#include <linux/math.h>
#include <linux/of.h>
#include <linux/scatterlist.h>
#include <linux/sched/mm.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/version.h>

#include <gcip/gcip-config.h>
#include <gcip/gcip-domain-pool.h>
#include <gcip/gcip-iommu.h>
#include <gcip/gcip-mem-pool.h>

#if HAS_IOVAD_BEST_FIT_ALGO
#include <linux/dma-iommu.h>
#endif

/* Macros for manipulating @gcip_map_flags parameter. */
#define GCIP_MAP_MASK(ATTR)                                                                        \
	((BIT_ULL(GCIP_MAP_FLAGS_##ATTR##_BIT_SIZE) - 1) << (GCIP_MAP_FLAGS_##ATTR##_OFFSET))
#define GCIP_MAP_MASK_DMA_DIRECTION GCIP_MAP_MASK(DMA_DIRECTION)
#define GCIP_MAP_MASK_DMA_COHERENT GCIP_MAP_MASK(DMA_COHERENT)
#define GCIP_MAP_MASK_DMA_ATTR GCIP_MAP_MASK(DMA_ATTR)
#define GCIP_MAP_MASK_RESTRICT_IOVA GCIP_MAP_MASK(RESTRICT_IOVA)

#define GCIP_MAP_FLAGS_GET_VALUE(ATTR, flags)                                                      \
	(((flags) & GCIP_MAP_MASK(ATTR)) >> (GCIP_MAP_FLAGS_##ATTR##_OFFSET))
#define GCIP_MAP_FLAGS_GET_DMA_DIRECTION(flags) GCIP_MAP_FLAGS_GET_VALUE(DMA_DIRECTION, flags)
#define GCIP_MAP_FLAGS_GET_DMA_COHERENT(flags) GCIP_MAP_FLAGS_GET_VALUE(DMA_COHERENT, flags)
#define GCIP_MAP_FLAGS_GET_DMA_ATTR(flags) GCIP_MAP_FLAGS_GET_VALUE(DMA_ATTR, flags)
#define GCIP_MAP_FLAGS_GET_RESTRICT_IOVA(flags) GCIP_MAP_FLAGS_GET_VALUE(RESTRICT_IOVA, flags)

/* Restricted IOVA ceiling is for components with 32-bit DMA windows */
#define GCIP_RESTRICT_IOVA_CEILING	UINT_MAX

/* Contains the information about dma-buf mapping. */
struct gcip_iommu_dma_buf_mapping {
	/* Stores the mapping information to the IOMMU domain. */
	struct gcip_iommu_mapping mapping;

	/* Following fields store the mapping information to the default domain. */

	/* Scatter-gather table which contains the mapping information. */
	struct sg_table *sgt_default;
	/* Shared dma-buf object. */
	struct dma_buf *dma_buf;
	/* Device attachment of dma-buf. */
	struct dma_buf_attachment *dma_buf_attachment;
};

/**
 * dma_info_to_prot - Translate DMA API directions and attributes to IOMMU API
 *                    page flags.
 * @dir: Direction of DMA transfer
 * @coherent: If true, create coherent mappings of the scatterlist.
 * @attrs: DMA attributes for the mapping
 *
 * See v5.15.94/source/drivers/iommu/dma-iommu.c#L418
 *
 * Return: corresponding IOMMU API page protection flags
 */
static int dma_info_to_prot(enum dma_data_direction dir, bool coherent, unsigned long attrs)
{
	int prot = coherent ? IOMMU_CACHE : 0;

	if (attrs & DMA_ATTR_PRIVILEGED)
		prot |= IOMMU_PRIV;

	switch (dir) {
	case DMA_BIDIRECTIONAL:
		return prot | IOMMU_READ | IOMMU_WRITE;
	case DMA_TO_DEVICE:
		return prot | IOMMU_READ;
	case DMA_FROM_DEVICE:
		return prot | IOMMU_WRITE;
	default:
		return 0;
	}
}

static inline unsigned long gcip_iommu_domain_shift(struct gcip_iommu_domain *domain)
{
	return __ffs(domain->domain_pool->granule);
}

static inline unsigned long gcip_iommu_domain_pfn(struct gcip_iommu_domain *domain, dma_addr_t iova)
{
	return iova >> gcip_iommu_domain_shift(domain);
}

static inline size_t gcip_iommu_domain_align(struct gcip_iommu_domain *domain, size_t size)
{
	return ALIGN(size, domain->domain_pool->granule);
}

static int iovad_initialize_domain(struct gcip_iommu_domain *domain)
{
	struct gcip_iommu_domain_pool *dpool = domain->domain_pool;

	init_iova_domain(&domain->iova_space.iovad, dpool->granule,
			 max_t(unsigned long, 1, dpool->base_daddr >> ilog2(dpool->granule)));

	if (dpool->reserved_size) {
		unsigned long shift = gcip_iommu_domain_shift(domain);
		unsigned long pfn_lo = dpool->reserved_base_daddr >> shift;
		unsigned long pfn_hi = (dpool->reserved_base_daddr + dpool->reserved_size) >> shift;

		reserve_iova(&domain->iova_space.iovad, pfn_lo, pfn_hi);
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
	return iova_domain_init_rcaches(&domain->iova_space.iovad);
#else
	return 0;
#endif
}

static void iovad_finalize_domain(struct gcip_iommu_domain *domain)
{
	put_iova_domain(&domain->iova_space.iovad);
}

static void iovad_enable_best_fit_algo(struct gcip_iommu_domain *domain)
{
#if HAS_IOVAD_BEST_FIT_ALGO
	domain->iova_space.iovad.best_fit = true;
#endif /* HAS_IOVAD_BEST_FIT_ALGO */
}

static dma_addr_t iovad_alloc_iova_space(struct gcip_iommu_domain *domain, size_t size,
					 bool restrict_iova)
{
	unsigned long iova_pfn, shift = gcip_iommu_domain_shift(domain);
	dma_addr_t iova_ceiling =
		restrict_iova ?
		min_t(dma_addr_t, GCIP_RESTRICT_IOVA_CEILING, domain->domain_pool->last_daddr)
		: domain->domain_pool->last_daddr;

	size = size >> shift;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
	/*
	 * alloc_iova_fast() makes use of a cache of recently freed IOVA pages which does not
	 * behave correctly for non-power-of-two amounts of pages. Round up the number of
	 * pages being allocated to ensure it's a safe number of pages.
	 *
	 * This rounding is done automatically as of 5.17
	 */
	if (size < (1 << (IOVA_RANGE_CACHE_MAX_SIZE - 1)))
		size = roundup_pow_of_two(size);
#endif

	iova_pfn = alloc_iova_fast(&domain->iova_space.iovad, size, iova_ceiling >> shift, true);
	return (dma_addr_t)iova_pfn << shift;
}

static void iovad_free_iova_space(struct gcip_iommu_domain *domain, dma_addr_t iova, size_t size)
{
	free_iova_fast(&domain->iova_space.iovad, gcip_iommu_domain_pfn(domain, iova),
		       size >> gcip_iommu_domain_shift(domain));
}

static const struct gcip_iommu_domain_ops iovad_ops = {
	.initialize_domain = iovad_initialize_domain,
	.finalize_domain = iovad_finalize_domain,
	.enable_best_fit_algo = iovad_enable_best_fit_algo,
	.alloc_iova_space = iovad_alloc_iova_space,
	.free_iova_space = iovad_free_iova_space,
};

static int mem_pool_initialize_domain(struct gcip_iommu_domain *domain)
{
	struct gcip_iommu_domain_pool *dpool = domain->domain_pool;
	size_t size = dpool->size;
	int ret;

	/* Restrict mem_pool IOVAs to 32 bits. */
	if (dpool->base_daddr + size > UINT_MAX)
		size = UINT_MAX - dpool->base_daddr;
	ret = gcip_mem_pool_init(&domain->iova_space.mem_pool, dpool->dev, dpool->base_daddr,
				 size, dpool->granule);

	dev_warn(domain->dev, "gcip-reserved-map is not supported in mem_pool mode.");

	return ret;
}

static void mem_pool_finalize_domain(struct gcip_iommu_domain *domain)
{
	gcip_mem_pool_exit(&domain->iova_space.mem_pool);
}

static void mem_pool_enable_best_fit_algo(struct gcip_iommu_domain *domain)
{
	gen_pool_set_algo(domain->iova_space.mem_pool.gen_pool, gen_pool_best_fit, NULL);
}

static dma_addr_t mem_pool_alloc_iova_space(struct gcip_iommu_domain *domain, size_t size,
					    bool restrict_iova)
{
	/* mem pool IOVA allocs are currently always restricted. */
	if (!restrict_iova)
		dev_warn_once(domain->dev, "IOVA size always restricted to 32-bit");
	return (dma_addr_t)gcip_mem_pool_alloc(&domain->iova_space.mem_pool, size);
}

static void mem_pool_free_iova_space(struct gcip_iommu_domain *domain, dma_addr_t iova, size_t size)
{
	gcip_mem_pool_free(&domain->iova_space.mem_pool, iova, size);
}

static const struct gcip_iommu_domain_ops mem_pool_ops = {
	.initialize_domain = mem_pool_initialize_domain,
	.finalize_domain = mem_pool_finalize_domain,
	.enable_best_fit_algo = mem_pool_enable_best_fit_algo,
	.alloc_iova_space = mem_pool_alloc_iova_space,
	.free_iova_space = mem_pool_free_iova_space,
};

/**
 * get_window_config() - Retrieve base address and size from device tree.
 * @dev: The device struct to get the device tree.
 * @name: The name of the target window.
 * @n_addr: The required number of cells to read the value of @addr.
 * @n_size: The required number of cells to read the value of @size.
 * @addr: The pointer of the base address to output the value. Set to 0 on failure.
 * @size: The pointer of the size to output the value. Set to 0 on failure.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int get_window_config(struct device *dev, char *name, int n_addr, int n_size,
			     dma_addr_t *addr, size_t *size)
{
	const __be32 *window;

	window = of_get_property(dev->of_node, name, NULL);
	if (!window) {
		*addr = *size = 0;
		return -ENODATA;
	}

	*addr = of_read_number(window, n_addr);
	*size = of_read_number(window + n_addr, n_size);

	return 0;
}

/*
 * Converts the flags with write-only dma direction to bidirectional because the read permission is
 * needed for prefetches.
 */
static void gcip_map_flags_adjust_dir(u64 *gcip_map_flags)
{
	if (GCIP_MAP_FLAGS_GET_DMA_DIRECTION(*gcip_map_flags) == DMA_FROM_DEVICE) {
		*gcip_map_flags &= ~GCIP_MAP_MASK_DMA_DIRECTION;
		*gcip_map_flags |= GCIP_MAP_FLAGS_DMA_DIRECTION_TO_FLAGS(DMA_BIDIRECTIONAL);
	}
}

/**
 * copy_alloc_sg_table(): Allocates a new sgt and copies the data from the old one.
 * @sgt_src: The source sg_table whose data will be copied to the new one.
 *
 * We will only copy the page information to the new sg_table, so the new sg_table will have the
 * same orig_nents and page information as the old one.
 *
 * Return: The new allocated sg_table with data copied from sgt_src or an error pointer on failure.
 */
static struct sg_table *copy_alloc_sg_table(struct sg_table *sgt_src)
{
	struct sg_table *sgt_dst;
	struct scatterlist *sgl_src, *sgl_dst;
	int ret, i;

	sgt_dst = kzalloc(sizeof(*sgt_dst), GFP_KERNEL);
	if (!sgt_dst) {
		ret = -ENOMEM;
		goto err_alloc_sgt;
	}

	ret = sg_alloc_table(sgt_dst, sgt_src->orig_nents, GFP_KERNEL);
	if (ret)
		goto err_alloc_sgl;

	sgl_dst = sgt_dst->sgl;
	for_each_sg(sgt_src->sgl, sgl_src, sgt_src->orig_nents, i) {
		sg_set_page(sgl_dst, sg_page(sgl_src), sgl_src->length, 0);
		sgl_dst = sg_next(sgl_dst);
	}

	return sgt_dst;

err_alloc_sgl:
	kfree(sgt_dst);
err_alloc_sgt:
	return ERR_PTR(ret);
}

/**
 * gcip_iommu_mapping_map_sgt(): Maps the scatter-gather table to the target IOMMU domain.
 * @mapping: The gcip mapping struct that contains the required information to map the sgt.
 *           The domain, sgt, gcip_map_flags should be set before calling this function.
 *
 * This function will map the scatter-gather table to the target IOMMU domain.
 * sgt->nents will be updated to the number of mapped chunks.
 * The mapping information will be stored in the mapping instance.
 *
 * Return: The number of the entries that are mapped successfully.
 */
static unsigned int gcip_iommu_mapping_map_sgt(struct gcip_iommu_mapping *mapping)
{
	struct gcip_iommu_domain *domain = mapping->domain;
	struct scatterlist *sgl = mapping->sgt->sgl;
	uint orig_nents = mapping->sgt->orig_nents;
	uint nents_mapped;

	gcip_map_flags_adjust_dir(&mapping->gcip_map_flags);

	nents_mapped = gcip_iommu_domain_map_sg(domain, sgl, orig_nents, mapping->gcip_map_flags);

	mapping->sgt->nents = nents_mapped;

	return nents_mapped;
}

/**
 * gcip_iommu_mapping_unmap_sgt() - Unmaps the sgt in the mapping.
 * @mapping: The container of domain and the sgt to be unmapped.
 */
static void gcip_iommu_mapping_unmap_sgt(struct gcip_iommu_mapping *mapping)
{
	gcip_iommu_domain_unmap_sg(mapping->domain, mapping->sgt->sgl, mapping->sgt->orig_nents);
}

/**
 * gcip_iommu_mapping_unmap_dma_buf() - Unmaps the dma buf mapping.
 * @mapping: The pointer of the mapping instance to be unmapped.
 *
 * Reverting gcip_iommu_domain_map_dma_buf()
 */
static void gcip_iommu_mapping_unmap_dma_buf(struct gcip_iommu_mapping *mapping)
{
	struct gcip_iommu_dma_buf_mapping *dmabuf_mapping =
		container_of(mapping, struct gcip_iommu_dma_buf_mapping, mapping);

	if (!mapping->domain->default_domain) {
		gcip_iommu_mapping_unmap_sgt(mapping);
		sg_free_table(mapping->sgt);
		kfree(mapping->sgt);
	}

	dma_buf_unmap_attachment(dmabuf_mapping->dma_buf_attachment, dmabuf_mapping->sgt_default,
				 mapping->dir);
	dma_buf_detach(dmabuf_mapping->dma_buf, dmabuf_mapping->dma_buf_attachment);
	dma_buf_put(dmabuf_mapping->dma_buf);
	kfree(dmabuf_mapping);
}

static inline void sync_sg_if_needed(struct gcip_iommu_mapping *mapping, bool for_device)
{
	u64 gcip_map_flags = mapping->gcip_map_flags;
	struct device *dev = mapping->domain->dev;
	struct sg_table *sgt = mapping->sgt;
	enum dma_data_direction dir = GCIP_MAP_FLAGS_GET_DMA_DIRECTION(gcip_map_flags);

	if (GCIP_MAP_FLAGS_GET_DMA_ATTR(gcip_map_flags) & DMA_ATTR_SKIP_CPU_SYNC)
		return;

	if (for_device)
		dma_sync_sg_for_device(dev, sgt->sgl, sgt->orig_nents, dir);
	else
		dma_sync_sg_for_cpu(dev, sgt->sgl, sgt->orig_nents, dir);
}

/**
 * gcip_pin_user_pages_fast() - Tries pin_user_pages_fast and returns success only if all pages are
 *                              pinned.
 * @pages: The allocated pages to be pinned.
 * @start_addr: The starting user address, must be page-aligned.
 * @num_pages: Same as gcip_iommu_alloc_and_pin_user_pages.
 * @gup_flags: The gup_flags used to pin user pages.
 * @pin_user_pages_lock: Same as gcip_iommu_alloc_and_pin_user_pages.
 *
 * The function will try pin_user_pages_fast.
 * If its return value equals @num_pages, returns @num_pages.
 * If only partial pages are pinned, unpins all pages and return 0.
 * Returns the error code otherwise.
 */
static int gcip_pin_user_pages_fast(struct page **pages, unsigned long start_addr, uint num_pages,
				    unsigned int gup_flags, struct mutex *pin_user_pages_lock)
{
	int ret, i;

	/*
	 * Provide protection around `pin_user_pages_fast` since it fails if called by more than one
	 * thread simultaneously.
	 */
	if (pin_user_pages_lock)
		mutex_lock(pin_user_pages_lock);

	ret = pin_user_pages_fast(start_addr, num_pages, gup_flags, pages);

	if (pin_user_pages_lock)
		mutex_unlock(pin_user_pages_lock);

	if (ret < num_pages) {
		for (i = 0; i < ret; i++)
			unpin_user_page(pages[i]);
		ret = 0;
	}

	return ret;
}

/**
 * gcip_pin_user_pages() - Try pin_user_pages_fast and try again with pin_user_pages if failed.
 * @dev: device for which the pages are being pinned, for logs.
 * @pages: The allocated pages to be pinned.
 * @start_addr: The starting user address, must be page-aligned.
 * @num_pages: Same as gcip_iommu_alloc_and_pin_user_pages.
 * @gup_flags: The gup_flags used to pin user pages.
 * @pin_user_pages_lock: Same as gcip_iommu_alloc_and_pin_user_pages.
 *
 * The return value and the partial pinned cases is handled the same as @gcip_pin_user_pages_fast.
 */
static int gcip_pin_user_pages(struct device *dev, struct page **pages, unsigned long start_addr,
			       uint num_pages, unsigned int gup_flags,
			       struct mutex *pin_user_pages_lock)
{
	int ret, i;
	__maybe_unused struct vm_area_struct **vmas = NULL;

	ret = gcip_pin_user_pages_fast(pages, start_addr, num_pages, gup_flags,
				       pin_user_pages_lock);
	if (ret == num_pages)
		return ret;

	dev_dbg(dev, "Failed to pin user pages in fast mode (ret=%d, addr=%lu, num_pages=%d)", ret,
		start_addr, num_pages);

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
	/* Allocate our own vmas array non-contiguous. */
	vmas = kvmalloc((num_pages * sizeof(*vmas)), GFP_KERNEL | __GFP_NOWARN);
	if (!vmas)
		return -ENOMEM;
#endif

	mmap_read_lock(current->mm);
	if (pin_user_pages_lock)
		mutex_lock(pin_user_pages_lock);

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
	ret = pin_user_pages(start_addr, num_pages, gup_flags, pages, vmas);
#else
	ret = pin_user_pages(start_addr, num_pages, gup_flags, pages);
#endif

	if (pin_user_pages_lock)
		mutex_unlock(pin_user_pages_lock);
	mmap_read_unlock(current->mm);

	kvfree(vmas);

	if (ret < num_pages) {
		if (ret > 0) {
			dev_err(dev, "Can only lock %u of %u pages requested", ret, num_pages);
			for (i = 0; i < ret; i++)
				unpin_user_page(pages[i]);
		}
		ret = 0;
	}

	return ret;
}

int gcip_iommu_domain_pool_init(struct gcip_iommu_domain_pool *pool, struct device *dev,
				dma_addr_t base_daddr, size_t iova_space_size, size_t granule,
				unsigned int num_domains, enum gcip_iommu_domain_type domain_type)
{
	int ret;

	ret = gcip_domain_pool_init(dev, &pool->domain_pool, num_domains);
	if (ret)
		return ret;

	pool->dev = dev;
	pool->base_daddr = base_daddr;
	pool->size = iova_space_size;
	pool->granule = granule;
	pool->best_fit = false;
	pool->domain_type = domain_type;

	if (dev->of_node && (!base_daddr || !iova_space_size)) {
		const __be32 *prop;
		u32 n_addr, n_size;

		prop = of_get_property(dev->of_node, "#dma-address-cells", NULL);
		n_addr = max_t(u32, 1, prop ? be32_to_cpup(prop) : of_n_addr_cells(dev->of_node));

		prop = of_get_property(dev->of_node, "#dma-size-cells", NULL);
		n_size = max_t(u32, 1, prop ? be32_to_cpup(prop) : of_n_size_cells(dev->of_node));

		ret = get_window_config(dev, "gcip-dma-window", n_addr, n_size, &pool->base_daddr,
					&pool->size);
		if (ret)
			dev_warn(dev, "Failed to find gcip-dma-window property");

		get_window_config(dev, "gcip-reserved-map", n_addr, n_size,
				  &pool->reserved_base_daddr, &pool->reserved_size);
	}

	if (!pool->base_daddr || !pool->size) {
		gcip_domain_pool_destroy(&pool->domain_pool);
		return -EINVAL;
	} else {
		pool->last_daddr = pool->base_daddr + pool->size - 1;
	}

	pool->min_pasid = 0;
	pool->max_pasid = 0;
#if HAS_IOMMU_PASID
	ida_init(&pool->pasid_pool);
#elif HAS_AUX_DOMAINS
	iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_AUX);
	if (!iommu_dev_feature_enabled(dev, IOMMU_DEV_FEAT_AUX))
		dev_warn(dev, "AUX domains not supported\n");
	else
		pool->aux_enabled = true;
#else
	dev_warn(dev, "Attaching additional domains not supported\n");
#endif

	dev_dbg(dev, "Init GCIP IOMMU domain pool, base_daddr=%#llx, size=%#zx", pool->base_daddr,
		pool->size);

	return 0;
}

void gcip_iommu_domain_pool_destroy(struct gcip_iommu_domain_pool *pool)
{
	gcip_domain_pool_destroy(&pool->domain_pool);
#if HAS_IOMMU_PASID
	ida_destroy(&pool->pasid_pool);
#endif
}

void gcip_iommu_domain_pool_enable_best_fit_algo(struct gcip_iommu_domain_pool *pool)
{
	if (pool->domain_type == GCIP_IOMMU_DOMAIN_TYPE_IOVAD && !HAS_IOVAD_BEST_FIT_ALGO) {
		dev_warn(pool->dev, "This env doesn't support best-fit algorithm with IOVAD");
		pool->best_fit = false;
	} else {
		pool->best_fit = true;
	}
}

struct gcip_iommu_domain *gcip_iommu_domain_pool_alloc_domain(struct gcip_iommu_domain_pool *pool)
{
	struct gcip_iommu_domain *gdomain;
	int ret;

	gdomain = devm_kzalloc(pool->dev, sizeof(*gdomain), GFP_KERNEL);
	if (!gdomain)
		return ERR_PTR(-ENOMEM);

	gdomain->dev = pool->dev;
	gdomain->domain_pool = pool;
	gdomain->pasid = INVALID_IOASID;
	gdomain->domain = gcip_domain_pool_alloc(&pool->domain_pool);
	if (IS_ERR_OR_NULL(gdomain->domain)) {
		ret = -ENOMEM;
		goto err_free_gdomain;
	}

	switch (pool->domain_type) {
	case GCIP_IOMMU_DOMAIN_TYPE_IOVAD:
		gdomain->ops = &iovad_ops;
		break;
	case GCIP_IOMMU_DOMAIN_TYPE_MEM_POOL:
		gdomain->ops = &mem_pool_ops;
		break;
	default:
		ret = -EINVAL;
		goto err_free_domain_pool;
	}

	ret = gdomain->ops->initialize_domain(gdomain);
	if (ret)
		goto err_free_domain_pool;

	if (pool->best_fit)
		gdomain->ops->enable_best_fit_algo(gdomain);

	return gdomain;

err_free_domain_pool:
	gcip_domain_pool_free(&pool->domain_pool, gdomain->domain);
err_free_gdomain:
	devm_kfree(pool->dev, gdomain);
	return ERR_PTR(ret);
}

void gcip_iommu_domain_pool_free_domain(struct gcip_iommu_domain_pool *pool,
					struct gcip_iommu_domain *domain)
{
	domain->ops->finalize_domain(domain);
	gcip_domain_pool_free(&pool->domain_pool, domain->domain);
	devm_kfree(pool->dev, domain);
}

void gcip_iommu_domain_pool_set_pasid_range(struct gcip_iommu_domain_pool *pool, ioasid_t min,
					    ioasid_t max)
{
	pool->min_pasid = min;
	pool->max_pasid = max;
}

static int _gcip_iommu_domain_pool_attach_domain(struct gcip_iommu_domain_pool *pool,
						 struct gcip_iommu_domain *domain)
{
	int ret = -EOPNOTSUPP, pasid = INVALID_IOASID;

#if HAS_IOMMU_PASID
	pasid = ida_alloc_range(&pool->pasid_pool, pool->min_pasid, pool->max_pasid, GFP_KERNEL);
	if (pasid < 0)
		return pasid;

	ret = iommu_attach_device_pasid(domain->domain, pool->dev, pasid);
	if (ret) {
		ida_free(&pool->pasid_pool, pasid);
		return ret;
	}

#elif HAS_AUX_DOMAINS
	if (!pool->aux_enabled)
		return -ENODEV;

	ret = iommu_aux_attach_device(domain->domain, pool->dev);
	if (ret)
		return ret;

	pasid = iommu_aux_get_pasid(domain->domain, pool->dev);
	if (pasid < pool->min_pasid || pasid > pool->max_pasid) {
		dev_warn(pool->dev, "Invalid PASID %d returned from iommu", pasid);
		iommu_aux_detach_device(domain->domain, pool->dev);
		return -EINVAL;
	}

#endif
	domain->pasid = pasid;
	return ret;
}

int gcip_iommu_domain_pool_attach_domain(struct gcip_iommu_domain_pool *pool,
					 struct gcip_iommu_domain *domain)
{

	if (domain->pasid != INVALID_IOASID)
		/* Already attached. */
		return domain->pasid;

	return _gcip_iommu_domain_pool_attach_domain(pool, domain);
}

void gcip_iommu_domain_pool_detach_domain(struct gcip_iommu_domain_pool *pool,
					  struct gcip_iommu_domain *domain)
{
	if (domain->pasid == INVALID_IOASID)
		return;
#if HAS_IOMMU_PASID
	iommu_detach_device_pasid(domain->domain, pool->dev, domain->pasid);
	ida_free(&pool->pasid_pool, domain->pasid);
#elif HAS_AUX_DOMAINS
	if (pool->aux_enabled)
		iommu_aux_detach_device(domain->domain, pool->dev);
#endif
	domain->pasid = INVALID_IOASID;
}

unsigned int gcip_iommu_domain_map_sg(struct gcip_iommu_domain *domain, struct scatterlist *sgl,
				      int nents, u64 gcip_map_flags)
{
	enum dma_data_direction dir = GCIP_MAP_FLAGS_GET_DMA_DIRECTION(gcip_map_flags);
	bool coherent = GCIP_MAP_FLAGS_GET_DMA_COHERENT(gcip_map_flags);
	unsigned long attrs = GCIP_MAP_FLAGS_GET_DMA_ATTR(gcip_map_flags);
	bool restrict_iova = GCIP_MAP_FLAGS_GET_RESTRICT_IOVA(gcip_map_flags);
	int i, prot = dma_info_to_prot(dir, coherent, attrs);
	struct scatterlist *sg;
	dma_addr_t iova;
	size_t iova_len = 0;
	ssize_t map_size;
	int ret;

	/* Calculates how much IOVA space we need. */
	for_each_sg(sgl, sg, nents, i)
		iova_len += sg->length;

	/* Allocates one continuous IOVA. */
	iova = domain->ops->alloc_iova_space(domain, gcip_iommu_domain_align(domain, iova_len),
					     restrict_iova);
	if (!iova) {
		dev_err(domain->dev, "iova alloc size %zu failed", iova_len);
		return 0;
	}

	/*
	 * Maps scatterlist to the allocated IOVA.
	 *
	 * It will iterate each scatter list segment in order and map them to the IOMMU domain
	 * as amount of the size of each segment successively.
	 * Returns an error on failure or the total length of mapped segments on success.
	 *
	 * Note: Before Linux 5.15, its return type was `size_t` and it returned 0 on failure.
	 *       To make it compatible with those old versions, we should cast the return value.
	 */
	map_size = (ssize_t)iommu_map_sg(domain->domain, iova, sgl, nents, prot);
	if (map_size < 0 || map_size < iova_len)
		goto err_free_iova;

	/*
	 * Fills out the mapping information. Each entry can be max UINT_MAX bytes, floored
	 * to the pool granule size.
	 */
	ret = 0;
	sg = sgl;
	while (iova_len) {
		size_t segment_len = min_t(size_t, iova_len,
					   UINT_MAX & ~(domain->domain_pool->granule - 1));

		sg_dma_address(sg) = iova;
		sg_dma_len(sg) = segment_len;
		iova += segment_len;
		iova_len -= segment_len;
		ret++;
		sg = sg_next(sg);
	}

	/* Return # of sg entries filled out above. */
	return ret;

err_free_iova:
	domain->ops->free_iova_space(domain, iova, gcip_iommu_domain_align(domain, iova_len));
	return 0;
}

void gcip_iommu_domain_unmap_sg(struct gcip_iommu_domain *domain, struct scatterlist *sgl,
				int nents)
{
	dma_addr_t iova = sg_dma_address(sgl);
	size_t iova_len = 0;
	struct scatterlist *sg;
	int i;

	for_each_sg(sgl, sg, nents, i) {
		uint s_len = sg_dma_len(sg);

		if (!s_len)
			break;
		iova_len += s_len;
	}

	iommu_unmap(domain->domain, iova, iova_len);
	domain->ops->free_iova_space(domain, iova, gcip_iommu_domain_align(domain, iova_len));
}

struct gcip_iommu_domain *gcip_iommu_get_domain_for_dev(struct device *dev)
{
	struct gcip_iommu_domain *gdomain;

	gdomain = devm_kzalloc(dev, sizeof(*gdomain), GFP_KERNEL);
	if (!gdomain)
		return ERR_PTR(-ENOMEM);

	gdomain->domain = iommu_get_domain_for_dev(dev);
	if (!gdomain->domain) {
		devm_kfree(dev, gdomain);
		return ERR_PTR(-ENODEV);
	}

	gdomain->dev = dev;
	gdomain->default_domain = true;
	gdomain->pasid = 0;

	return gdomain;
}

u64 gcip_iommu_encode_gcip_map_flags(enum dma_data_direction dir, bool coherent,
				     unsigned long dma_attrs, bool restrict_iova)
{
	return GCIP_MAP_FLAGS_DMA_DIRECTION_TO_FLAGS(dir) |
	       GCIP_MAP_FLAGS_DMA_COHERENT_TO_FLAGS(coherent) |
	       GCIP_MAP_FLAGS_DMA_ATTR_TO_FLAGS(dma_attrs) |
	       GCIP_MAP_FLAGS_RESTRICT_IOVA_TO_FLAGS(restrict_iova);
}

/* The helper function of gcip_iommu_dmabuf_map_show for printing multi-entry mappings. */
static void entry_show_dma_addrs(struct gcip_iommu_mapping *mapping, struct seq_file *s)
{
	struct sg_table *sgt = mapping->sgt;
	struct scatterlist *sg = sgt->sgl;
	uint i;

	if (sgt->nents > 1) {
		seq_puts(s, " dma=[");
		for (i = 0; i < sgt->nents; i++) {
			if (i)
				seq_puts(s, ", ");
			seq_printf(s, "%pad", &sg_dma_address(sg));
			sg = sg_next(sg);
		}
		seq_puts(s, "]");
	}
	seq_puts(s, "\n");
}

void gcip_iommu_dmabuf_map_show(struct gcip_iommu_mapping *mapping, struct seq_file *s)
{
	static const char *dma_dir_tbl[4] = { "rw", "r", "w", "?" };
	struct gcip_iommu_dma_buf_mapping *dmabuf_mapping =
		container_of(mapping, struct gcip_iommu_dma_buf_mapping, mapping);

	seq_printf(s, "  %pad %lu %s %s %pad", &mapping->device_address,
		   DIV_ROUND_UP(mapping->size, PAGE_SIZE), dma_dir_tbl[mapping->dir],
		   dmabuf_mapping->dma_buf->exp_name,
		   &sg_dma_address(dmabuf_mapping->sgt_default->sgl));
	entry_show_dma_addrs(mapping, s);
}

int gcip_iommu_get_offset_npages(struct device *dev, u64 host_address, size_t size, ulong *off_ptr,
				 uint *n_pg_ptr)
{
	ulong offset;
	uint num_pages;

	offset = host_address & (PAGE_SIZE - 1);
	if (unlikely(offset + size < offset)) {
		dev_dbg(dev, "Overflow: offset(%lu) + size(%lu) < offset(%lu)", offset, size,
			offset);
		return -EFAULT;
	}

	num_pages = DIV_ROUND_UP((size + offset), PAGE_SIZE);
	if (unlikely(num_pages * PAGE_SIZE < size + offset)) {
		dev_dbg(dev, "Overflow: num_pages(%u) * PAGE_SIZE(%lu) < size(%lu) + offset(%lu)",
			num_pages, PAGE_SIZE, offset, size);
		return -EFAULT;
	}

	*n_pg_ptr = num_pages;
	*off_ptr = offset;

	return 0;
}

unsigned int gcip_iommu_get_gup_flags(u64 host_addr, struct device *dev)
{
	struct vm_area_struct *vma;
	unsigned int gup_flags;

	mmap_read_lock(current->mm);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 14, 1)
	vma = find_extend_vma(current->mm, host_addr & PAGE_MASK);
#else
	vma = vma_lookup(current->mm, host_addr & PAGE_MASK);
#endif
	mmap_read_unlock(current->mm);

	if (!vma) {
		dev_dbg(dev, "unable to find address in VMA, assuming buffer writable");
		gup_flags = FOLL_LONGTERM | FOLL_WRITE;
	} else if (vma->vm_flags & VM_WRITE) {
		gup_flags = FOLL_LONGTERM | FOLL_WRITE;
	} else {
		gup_flags = FOLL_LONGTERM;
	}

	return gup_flags;
}

/* TODO(302510715): Put atomic64_add here after the buffer mapping process is moved to GCIP. */
struct page **gcip_iommu_alloc_and_pin_user_pages(struct device *dev, u64 host_address,
						  uint num_pages, unsigned int *gup_flags,
						  struct mutex *pin_user_pages_lock)
{
	unsigned long start_addr = host_address & PAGE_MASK;
	struct page **pages;
	int ret;

	/*
	 * "num_pages" is decided from user-space arguments, don't show warnings
	 * when facing malicious input.
	 */
	pages = kvmalloc((num_pages * sizeof(*pages)), GFP_KERNEL | __GFP_NOWARN);
	if (!pages)
		return ERR_PTR(-ENOMEM);

	ret = gcip_pin_user_pages(dev, pages, start_addr, num_pages, *gup_flags,
				  pin_user_pages_lock);
	if (ret == num_pages)
		return pages;

	if (!(*gup_flags & FOLL_WRITE))
		goto err_pin_read_only;

	dev_dbg(dev, "pin failed with fault, assuming buffer is read-only");
	*gup_flags &= ~FOLL_WRITE;

	ret = gcip_pin_user_pages(dev, pages, start_addr, num_pages, *gup_flags,
				  pin_user_pages_lock);
	if (ret == num_pages)
		return pages;

err_pin_read_only:
	kvfree(pages);
	dev_err(dev, "Pin user pages failed: user_add=%#llx, num_pages=%u, %s, ret=%d\n",
		host_address, num_pages, ((*gup_flags & FOLL_WRITE) ? "writeable" : "read-only"),
		ret);

	return ERR_PTR(ret >= 0 ? -EFAULT : ret);
}

struct gcip_iommu_mapping *gcip_iommu_domain_map_sgt(struct gcip_iommu_domain *domain,
						     struct sg_table *sgt, u64 gcip_map_flags)
{
	struct gcip_iommu_mapping *mapping;
	int ret;
	struct scatterlist *sl;
	int i;

	mapping = kzalloc(sizeof(*mapping), GFP_KERNEL);
	if (!mapping)
		return ERR_PTR(-ENOMEM);

	mapping->domain = domain;
	mapping->sgt = sgt;
	mapping->gcip_map_flags = gcip_map_flags;
	mapping->type = GCIP_IOMMU_MAPPING_BUFFER;
	ret = gcip_iommu_mapping_map_sgt(mapping);
	if (!ret) {
		ret = -ENOSPC;
		dev_err(domain->dev, "Failed to map sgt to domain (ret=%d)\n", ret);
		goto err_map_sgt;
	}
	mapping->device_address = sg_dma_address(sgt->sgl);

	mapping->size = 0;
	for_each_sg(sgt->sgl, sl, sgt->nents, i)
		mapping->size += sg_dma_len(sl);

	/*
	 * TODO(b/302510715): Set mapping->dir and consider the offset of device_address here after
	 *                    introducing `gcip_iommu_domain_map_buffer` for buffer mapping.
	 */

	sync_sg_if_needed(mapping, true);

	return mapping;

err_map_sgt:
	kfree(mapping);
	return ERR_PTR(ret);
}

struct gcip_iommu_mapping *gcip_iommu_domain_map_dma_buf(struct gcip_iommu_domain *domain, int fd,
							 u64 gcip_map_flags)
{
	struct device *dev = domain->dev;
	struct dma_buf *dmabuf;
	struct dma_buf_attachment *attachment;
	struct gcip_iommu_dma_buf_mapping *dmabuf_mapping;
	struct gcip_iommu_mapping *mapping;
	enum dma_data_direction dir = GCIP_MAP_FLAGS_GET_DMA_DIRECTION(gcip_map_flags);
	int nents_mapped;
	void *ret;

	if (!valid_dma_direction(dir)) {
		dev_err(dev, "Invalid dma data direction (dir=%d)\n", dir);
		return ERR_PTR(-EINVAL);
	}

	dmabuf_mapping = kzalloc(sizeof(*dmabuf_mapping), GFP_KERNEL);
	if (!dmabuf_mapping)
		return ERR_PTR(-ENOMEM);

	dmabuf = dma_buf_get(fd);
	if (IS_ERR(dmabuf)) {
		ret = ERR_CAST(dmabuf);
		dev_err(dev, "Failed to get dma-buf (ret=%ld)\n", PTR_ERR(ret));
		goto err_dma_buf_get;
	}

	attachment = dma_buf_attach(dmabuf, dev);
	if (IS_ERR(attachment)) {
		ret = ERR_CAST(attachment);
		dev_err(dev, "Failed to attach dma-buf (ret=%ld, name=%s)\n", PTR_ERR(ret),
			dmabuf->name);
		goto err_attach;
	}
#if GCIP_IS_GKI
	attachment->dma_map_attrs |= GCIP_MAP_FLAGS_GET_DMA_ATTR(gcip_map_flags);
#endif

	/* Map the attachment into the default domain. */
	dmabuf_mapping->dma_buf_attachment = attachment;
	dmabuf_mapping->sgt_default = dma_buf_map_attachment(attachment, dir);
	if (IS_ERR(dmabuf_mapping->sgt_default)) {
		ret = ERR_CAST(dmabuf_mapping->sgt_default);
		dev_err(dev, "Failed to get sgt from attachment (ret=%ld, name=%s, size=%lu)\n",
			PTR_ERR(ret), dmabuf->name, dmabuf->size);
		goto err_map_attachment;
	}

	mapping = &dmabuf_mapping->mapping;
	mapping->domain = domain;
	mapping->size = dmabuf->size;
	mapping->type = GCIP_IOMMU_MAPPING_DMA_BUF;
	mapping->dir = dir;
	mapping->gcip_map_flags = gcip_map_flags;

	if (domain->default_domain) {
		mapping->sgt = dmabuf_mapping->sgt_default;
		mapping->device_address = sg_dma_address(dmabuf_mapping->sgt_default->sgl);
		goto out_default_domain;
	}

	mapping->sgt = copy_alloc_sg_table(dmabuf_mapping->sgt_default);
	if (IS_ERR(mapping->sgt)) {
		ret = ERR_CAST(mapping->sgt);
		dev_err(dev, "Failed to copy sg_table (ret=%ld)\n", PTR_ERR(ret));
		goto err_copy_sgt;
	}

	nents_mapped = gcip_iommu_mapping_map_sgt(mapping);
	if (!nents_mapped) {
		ret = ERR_PTR(-ENOSPC);
		dev_err(dev, "Failed to map dmabuf to IOMMU domain (ret=%ld)\n", PTR_ERR(ret));
		goto err_map_sg;
	}
	mapping->device_address = sg_dma_address(mapping->sgt->sgl);

out_default_domain:
	sync_sg_if_needed(mapping, true);

	/*
	 * No need to increase the reference to dmabuf here because it's already increased by
	 * dma_buf_get() above.
	 */
	dmabuf_mapping->dma_buf = dmabuf;

	return mapping;

err_map_sg:
	sg_free_table(mapping->sgt);
	kfree(mapping->sgt);
err_copy_sgt:
	dma_buf_unmap_attachment(attachment, dmabuf_mapping->sgt_default, dir);
err_map_attachment:
	dma_buf_detach(dmabuf, attachment);
err_attach:
	dma_buf_put(dmabuf);
err_dma_buf_get:
	kfree(dmabuf_mapping);
	return ret;
}

void gcip_iommu_mapping_unmap(struct gcip_iommu_mapping *mapping)
{
	sync_sg_if_needed(mapping, false);

	if (mapping->type == GCIP_IOMMU_MAPPING_BUFFER) {
		gcip_iommu_mapping_unmap_sgt(mapping);
		/*
		 * TODO(b/302127145): Refactor the function to make buffer and dmabuf interface
		 *                    symmetric.
		 */
		kfree(mapping);
	} else if (mapping->type == GCIP_IOMMU_MAPPING_DMA_BUF) {
		gcip_iommu_mapping_unmap_dma_buf(mapping);
	}
}
