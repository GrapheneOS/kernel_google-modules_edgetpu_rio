/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Manages GCIP IOMMU domains and allocates/maps IOVAs.
 *
 * One can replace allocating IOVAs via Linux DMA interface which will allocate and map them to
 * the default IOMMU domain with this framework. This framework will allocate and map IOVAs to the
 * specific IOMMU domain directly. This has following two advantages:
 *
 * - Can remove the mapping time by once as it maps to the target IOMMU domain directly.
 * - IOMMU domains don't have to share the total capacity.
 *
 * GCIP IOMMU domain is implemented by utilizing multiple kinds of IOVA space pool:
 * - struct iova_domain
 * - struct gcip_mem_pool
 *
 * Copyright (C) 2023 Google LLC
 */

#ifndef __GCIP_IOMMU_H__
#define __GCIP_IOMMU_H__

#include <linux/device.h>
#include <linux/dma-direction.h>
#include <linux/iommu.h>
#include <linux/iova.h>
#include <linux/scatterlist.h>
#include <linux/seq_file.h>
#include <linux/version.h>

#include <gcip/gcip-domain-pool.h>
#include <gcip/gcip-mem-pool.h>

/*
 * TODO(b/277649169) Best fit IOVA allocator was removed in 6.1 GKI
 * The API needs to either be upstreamed, integrated into this driver, or disabled for 6.1
 * compatibility. For now, disable best-fit on all non-Android kernels and any GKI > 5.15.
 */
#define HAS_IOVAD_BEST_FIT_ALGO                                                                    \
	(LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0) &&                                          \
	 (IS_ENABLED(CONFIG_GCIP_TEST) || IS_ENABLED(CONFIG_ANDROID)))

/* This feature was actually added in Linux 6.2, but backported to the 6.1 Android Common Kernel.*/
#define HAS_IOMMU_PASID (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))

#define HAS_AUX_DOMAINS (LINUX_VERSION_CODE <= KERNEL_VERSION(5, 17, 0))

#if HAS_IOMMU_PASID
#include <linux/idr.h>
#endif

/*
 * Helpers for manipulating @gcip_map_flags parameter of the `gcip_iommu_domain_{map,unmap}_sg`
 * functions.
 */
#define GCIP_MAP_FLAGS_DMA_DIRECTION_OFFSET 0
#define GCIP_MAP_FLAGS_DMA_DIRECTION_BIT_SIZE 2
#define GCIP_MAP_FLAGS_DMA_DIRECTION_TO_FLAGS(dir)                                                 \
	((u64)(dir) << GCIP_MAP_FLAGS_DMA_DIRECTION_OFFSET)

#define GCIP_MAP_FLAGS_DMA_COHERENT_OFFSET                                                         \
	(GCIP_MAP_FLAGS_DMA_DIRECTION_OFFSET + GCIP_MAP_FLAGS_DMA_DIRECTION_BIT_SIZE)
#define GCIP_MAP_FLAGS_DMA_COHERENT_BIT_SIZE 1
#define GCIP_MAP_FLAGS_DMA_COHERENT_TO_FLAGS(coherent)                                             \
	((u64)(coherent) << GCIP_MAP_FLAGS_DMA_COHERENT_OFFSET)

#define GCIP_MAP_FLAGS_DMA_ATTR_OFFSET                                                             \
	(GCIP_MAP_FLAGS_DMA_COHERENT_OFFSET + GCIP_MAP_FLAGS_DMA_COHERENT_BIT_SIZE)
#define GCIP_MAP_FLAGS_DMA_ATTR_BIT_SIZE 10
#define GCIP_MAP_FLAGS_DMA_ATTR_TO_FLAGS(attr) ((u64)(attr) << GCIP_MAP_FLAGS_DMA_ATTR_OFFSET)

#define GCIP_MAP_FLAGS_RESTRICT_IOVA_OFFSET                                                        \
	(GCIP_MAP_FLAGS_DMA_ATTR_OFFSET + GCIP_MAP_FLAGS_DMA_ATTR_BIT_SIZE)
#define GCIP_MAP_FLAGS_RESTRICT_IOVA_BIT_SIZE 1
#define GCIP_MAP_FLAGS_RESTRICT_IOVA_TO_FLAGS(restrict)                                            \
	((u64)(restrict) << GCIP_MAP_FLAGS_RESTRICT_IOVA_OFFSET)

/*
 * Bitfields of @gcip_map_flags:
 *   [1:0]   - DMA_DIRECTION:
 *               00 = DMA_BIDIRECTIONAL (host/device can write buffer)
 *               01 = DMA_TO_DEVICE     (host can write buffer)
 *               10 = DMA_FROM_DEVICE   (device can write buffer)
 *               (See [REDACTED]
 *   [2:2]   - Coherent Mapping:
 *               0 = Create non-coherent mappings of the buffer.
 *               1 = Create coherent mappings of the buffer.
 *   [12:3]  - DMA_ATTR:
 *               (See [REDACTED]
 *   [13:13] - RESTRICT_IOVA:
 *               Restrict the IOVA assignment to 32 bit address window.
 *   [63:14] - RESERVED
 *               Set RESERVED bits to 0 to ensure backwards compatibility.
 *
 * One can use gcip_iommu_encode_gcip_map_flags or `GCIP_MAP_FLAGS_DMA_*_TO_FLAGS` macros to
 * generate a flag.
 */

struct gcip_iommu_domain_ops;

/**
 * enum gcip_iommu_mapping_type - Indicates the type of the gcip_iommu_mapping.
 * GCIP_IOMMU_MAPPING_BUFFER: The mapping of a normal buffer that mapped to the domain directly.
 * GCIP_IOMMU_MAPPING_DMA_BUF: The mapping of a DMA buffer that mapped to domain with 2 steps.
 */
enum gcip_iommu_mapping_type {
	GCIP_IOMMU_MAPPING_BUFFER,
	GCIP_IOMMU_MAPPING_DMA_BUF,
};

/**
 * struct gcip_iommu_mapping - Contains the information of sgt mapping to the domain.
 * @type: Type of the mapping.
 * @domain: IOMMU domain where the @sgt is mapped.
 * @device_address: Assigned device address.
 * @size: Size of mapped buffer.
 * @sgt: This pointer will be set to a new allocated Scatter-gather table which contains the mapping
 *       information to the given domain received from the custom IOVA allocator.
 *       If the given domain is the default domain, the pointer will be set to the sgt received from
 *       default allocator.
 * @dir: The data direction that user tried to map.
 *       This value may be different from the one encoded in gcip_map_flags.
 * @gcip_map_flags: The flags used to create the mapping, which can be encoded with
 *                  gcip_iommu_encode_gcip_map_flags() or `GCIP_MAP_FLAGS_DMA_*_TO_FLAGS` macros.
 * @owning_mm: For holding a reference to MM.
 */
struct gcip_iommu_mapping {
	enum gcip_iommu_mapping_type type;
	struct gcip_iommu_domain *domain;
	dma_addr_t device_address;
	size_t size;
	uint num_pages;
	struct sg_table *sgt;
	enum dma_data_direction dir;
	u64 gcip_map_flags;
	/*
	 * TODO(b/302510715): Use another wrapper struct to contain this because it is used in
	 *                    buffer mapping only.
	 */
	struct mm_struct *owning_mm;
};

/*
 * Type of IOVA space pool that IOMMU domain will utilize.
 * Regardless of the type, its functionality will be the same. However, its implementation might be
 * different. For example, iova_domain uses red-black tree for the memory management, but gen_pool
 * uses bitmap. Therefore, their performance might be different and the kernel drivers can choose
 * which one to use according to its real use cases and the performance.
 */
enum gcip_iommu_domain_type {
	/* Uses iova_domain. */
	GCIP_IOMMU_DOMAIN_TYPE_IOVAD,
	/* Uses gcip_mem_pool which is based on gen_pool. */
	GCIP_IOMMU_DOMAIN_TYPE_MEM_POOL,
};

/*
 * IOMMU domain pool.
 *
 * It manages the pool of IOMMU domains. Also, it specifies the base address and the size of IOMMU
 * domains. Also, one can choose the data structure and algorithm of IOVA space management.
 */
struct gcip_iommu_domain_pool {
	struct device *dev;
	struct gcip_domain_pool domain_pool;
	dma_addr_t base_daddr;
	/* Will hold (base_daddr + size - 1) to prevent calculating it every IOVAD mappings. */
	dma_addr_t last_daddr;
	size_t size;
	dma_addr_t reserved_base_daddr;
	size_t reserved_size;
	size_t granule;
	bool best_fit;
	enum gcip_iommu_domain_type domain_type;
	ioasid_t min_pasid;
	ioasid_t max_pasid;
#if HAS_IOMMU_PASID
	struct ida pasid_pool;
#elif HAS_AUX_DOMAINS
	bool aux_enabled;
#endif
};

/*
 * Wrapper of iommu_domain.
 * It has its own IOVA space pool based on iova_domain or gcip_mem_pool. One can choose one of them
 * when calling the `gcip_iommu_domain_pool_init` function. See `enum gcip_iommu_domain_type`
 * for details.
 */
struct gcip_iommu_domain {
	struct device *dev;
	struct gcip_iommu_domain_pool *domain_pool;
	struct iommu_domain *domain;
	bool default_domain;
	union {
		struct iova_domain iovad;
		struct gcip_mem_pool mem_pool;
	} iova_space;
	const struct gcip_iommu_domain_ops *ops;
	ioasid_t pasid; /* Only valid if attached */
};

/*
 * Holds operators which will be set according to the @domain_type.
 * These callbacks will be filled automatically when a `struct gcip_iommu_domain` is allocated.
 */
struct gcip_iommu_domain_ops {
	/* Initializes pool of @domain. */
	int (*initialize_domain)(struct gcip_iommu_domain *domain);
	/* Destroyes pool of @domain */
	void (*finalize_domain)(struct gcip_iommu_domain *domain);
	/*
	 * Enables best-fit algorithm for the memory management.
	 * Only domains which are allocated after calling this callback will be affected.
	 */
	void (*enable_best_fit_algo)(struct gcip_iommu_domain *domain);
	/* Allocates @size of IOVA space, optionally restricted to 32 bits, returns start IOVA. */
	dma_addr_t (*alloc_iova_space)(struct gcip_iommu_domain *domain, size_t size,
				       bool restrict_iova);
	/* Releases @size of buffer which was allocated to @iova. */
	void (*free_iova_space)(struct gcip_iommu_domain *domain, dma_addr_t iova, size_t size);
};

/*
 * Initializes an IOMMU domain pool.
 *
 * One can specify the base DMA address and IOVA space size via @base_daddr and @iova_space_size
 * parameters. If any of them is 0, it will try to parse "gcip-dma-window" property from the device
 * tree of @dev.
 *
 * If the base DMA address and IOVA space size are set successfully (i.e., larger than 0), IOMMU
 * domains allocated by this domain pool will have their own IOVA space pool and will map buffers
 * to their own IOMMU domain directly.
 * If either DMA address or IOVA space size are not set correctly, returns -EINVAL.
 *
 * @pool: IOMMU domain pool to be initialized.
 * @dev: Device where to parse "gcip-dma-window" property.
 * @base_addr: The base address of IOVA space. Must be greater than 0 and a multiple of @granule.
 * @iova_space_size: The size of the IOVA space. @size must be a multiple of @granule.
 * @granule: The granule when invoking the IOMMU domain pool. Must be a power of 2.
 * @num_domains: The number of IOMMU domains.
 * @domain_type: Type of the IOMMU domain.
 *
 * Returns 0 on success or negative error value.
 */
int gcip_iommu_domain_pool_init(struct gcip_iommu_domain_pool *pool, struct device *dev,
				dma_addr_t base_daddr, size_t iova_space_size, size_t granule,
				unsigned int num_domains, enum gcip_iommu_domain_type domain_type);

/*
 * Destroys an IOMMU domain pool.
 *
 * @pool: IOMMU domain pool to be destroyed.
 */
void gcip_iommu_domain_pool_destroy(struct gcip_iommu_domain_pool *pool);

/*
 * Enables the best fit algorithm for allocating an IOVA space.
 * It affects domains which are allocated after calling this function only.
 *
 * @pool: IOMMU domain pool to be enabled.
 */
void gcip_iommu_domain_pool_enable_best_fit_algo(struct gcip_iommu_domain_pool *pool);

/*
 * Allocates a GCIP IOMMU domain.
 *
 * @pool: IOMMU domain pool.
 *
 * Returns a pointer of allocated domain on success or an error pointer on failure.
 */
struct gcip_iommu_domain *gcip_iommu_domain_pool_alloc_domain(struct gcip_iommu_domain_pool *pool);

/*
 * Releases a GCIP IOMMU domain.
 *
 * Before calling this function, you must unmap all IOVAs by calling `gcip_iommu_domain_unmap{_sg}`
 * functions.
 *
 * @pool: IOMMU domain pool.
 * @domain: GCIP IOMMU domain to be released.
 */
void gcip_iommu_domain_pool_free_domain(struct gcip_iommu_domain_pool *pool,
					struct gcip_iommu_domain *domain);

/* Sets the range of valid PASIDs to be used when attaching a domain
 *
 * @min: The smallest acceptable value to be assigned to an attached domain
 * @max: The largest acceptable value to be assigned to an attached domain
 */
void gcip_iommu_domain_pool_set_pasid_range(struct gcip_iommu_domain_pool *pool, ioasid_t min,
					    ioasid_t max);

/*
 * Attaches a GCIP IOMMU domain and sets the obtained PASID
 *
 * Before calling this function, you must set the valid PASID range by calling
 * `gcip_iommu_domain_pool_set_pasid_range()`.
 *
 * @pool: IOMMU domain pool @domain was allocated from
 * @domain: The GCIP IOMMU domain to attach
 *
 * On success, @domain->pasid will be set to obtained PASID
 *
 * Returns:
 * * 0 - Domain successfully attached with a PASID
 * * -ENOSYS - This device does not support attaching multiple domains
 * * other   - Failed to attach the domain or obtain a PASID for it
 */
int gcip_iommu_domain_pool_attach_domain(struct gcip_iommu_domain_pool *pool,
					 struct gcip_iommu_domain *domain);

/*
 * Detaches a GCIP IOMMU domain
 *
 * @pool: IOMMU domain pool @domain was allocated from and attached by
 * @domain: The GCIP IOMMU domain to detach
 */
void gcip_iommu_domain_pool_detach_domain(struct gcip_iommu_domain_pool *pool,
					  struct gcip_iommu_domain *domain);

/* TODO(b/302127145): Change this function to a static function. */
/*
 * Allocates an IOVA for the scatterlist and maps it to @domain.
 *
 * @domain: GCIP IOMMU domain which manages IOVA addresses.
 * @sgl: Scatterlist to be mapped.
 * @nents: The number of entries in @sgl.
 * @gcip_map_flags: Flags indicating mapping attributes, which can be encoded with
 *                  gcip_iommu_encode_gcip_map_flags() or `GCIP_MAP_FLAGS_DMA_*_TO_FLAGS` macros.
 *
 * Returns the number of entries which are mapped to @domain. Returns 0 if it fails.
 */
unsigned int gcip_iommu_domain_map_sg(struct gcip_iommu_domain *domain, struct scatterlist *sgl,
				      int nents, u64 gcip_map_flags);

/* TODO(b/302127145): Change this function to a static function. */
/*
 * Unmaps an IOVA which was mapped for the scatterlist.
 *
 * @domain: GCIP IOMMU domain which manages IOVA addresses.
 * @sgl: Scatterlist to be unmapped.
 */
void gcip_iommu_domain_unmap_sg(struct gcip_iommu_domain *domain, struct scatterlist *sgl,
				int nents);

/*
 * Returns a default GCIP IOMMU domain.
 *
 * @dev: Device where to fetch the default IOMMU domain.
 */
struct gcip_iommu_domain *gcip_iommu_get_domain_for_dev(struct device *dev);

/*  Encodes the gcip_map_flags from dma_data_direct, coherent, dma_attrs, and restrict_iova info. */
u64 gcip_iommu_encode_gcip_map_flags(enum dma_data_direction dir, bool coherent,
				     unsigned long dma_attrs, bool restrict_iova);

/**
 * gcip_iommu_dmabuf_map_show() - Write the dma-buf mapping information to the seq_file.
 * @mapping: The container of the mapping info.
 * @s: The seq_file that the mapping info should be written to.
 *
 * Following information will be written to the seq_file:
 * 1. Device addresses of the related domains.
 * 2. Number of pages.
 * 3. DMA data direction.
 * 4. The name of the dmabuf.
 */
void gcip_iommu_dmabuf_map_show(struct gcip_iommu_mapping *mapping, struct seq_file *s);

/**
 * gcip_iommu_domain_map_dma_buf() - Maps the DMA buffer to the target IOMMU domain.
 * @domain: The desired IOMMU domain where the DMA buffer should be mapped.
 * @fd: The file descripter which will be used to retrieved dma_buf.
 * @gcip_map_flags: The flags used to create the mapping, which can be encoded with
 *                  gcip_iommu_encode_gcip_map_flags() or `GCIP_MAP_FLAGS_DMA_*_TO_FLAGS` macros.
 *
 * The DMA buffer will be mapped to the default domain first to get a scatter-gather table.
 * The received sgt will be copied to a new sgt and the new one will be mapped to the target domain.
 * The IOVAs of those domains may be different and the mappings will be released at once by calling
 * `gcip_iommu_mapping_unmap`.
 *
 * Return: The mapping of the desired DMA buffer with type GCIP_IOMMU_MAPPING_DMA_BUF
 *         or an error pointer on failure.
 */
struct gcip_iommu_mapping *gcip_iommu_domain_map_dma_buf(struct gcip_iommu_domain *domain, int fd,
							 u64 gcip_map_flags);

/**
 * gcip_iommu_domain_map_buffer() - Maps the buffer to the target IOMMU domain.
 * @domain: The desired IOMMU domain where the buffer should be mapped.
 * @host_address: The starting address of the buffer.
 * @size: The size of the buffer.
 * @gcip_map_flags: The flags used to create the mapping, which can be encoded with
 *                  gcip_iommu_encode_gcip_map_flags() or `GCIP_MAP_FLAGS_DMA_*_TO_FLAGS` macros.
 * @pin_user_pages_lock: The lock for pinning user pages.
 *
 * Following things are done in this function:
 * 1. Pin user pages.
 * 2. Allocate corresponding sg_table.
 * 3. Map the sg_table to the target domain.
 * 4. Create the desired mapping.
 *
 * Return: The mapping of the desired buffer with type GCIP_IOMMU_MAPPING_BUFFER or an error pointer
 *         on failure.
 */
struct gcip_iommu_mapping *gcip_iommu_domain_map_buffer(struct gcip_iommu_domain *domain,
							u64 host_address, size_t size,
							u64 gcip_map_flags,
							struct mutex *pin_user_pages_lock);

/**
 * gcip_iommu_mapping_unmap() - Unmaps the mapping depends on its type.
 * @mapping: The pointer of the mapping instance to be unmapped.
 *
 * Reverting either gcip_iommu_domain_map_dma_buf() or gcip_iommu_domain_map_buffer().
 *
 * The @mapping->gcip_map_flags will be used for unmapping the buffer, it can be modified if
 * necessary such as adding DMA_ATTR_SKIP_CPU_SYNC flag.
 * In most scenarios the we should use the same flag which we used while mapping especially for
 * direction, coherent, and iova_restrict.
 */
void gcip_iommu_mapping_unmap(struct gcip_iommu_mapping *mapping);

#endif /* __GCIP_IOMMU_H__ */
