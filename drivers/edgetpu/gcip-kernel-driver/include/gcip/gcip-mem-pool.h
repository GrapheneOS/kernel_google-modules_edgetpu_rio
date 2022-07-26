/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A simple memory allocator to help allocating reserved memory pools.
 *
 * Copyright (C) 2022 Google LLC
 */

#ifndef __GCIP_MEM_POOL_H__
#define __GCIP_MEM_POOL_H__

#include <linux/device.h>
#include <linux/genalloc.h>
#include <linux/types.h>

struct gcip_mem_pool {
	struct device *dev;
	struct gen_pool *gen_pool;
	phys_addr_t base_paddr;
	size_t granule;
};

/*
 * Initializes the memory pool object.
 *
 * @pool: The memory pool object to be initialized.
 * @dev: Used for logging only.
 * @base_paddr: The base physical address of the pool. Must be greater than 0 and a multiple of
 *              @granule.
 * @size: The size of the pool. @size should be a multiple of @granule.
 * @granule: The granule when invoking the allocator. Should be a power of 2.
 *
 * Returns 0 on success, a negative errno otherwise.
 *
 * Call gcip_mem_pool_exit() to release the resources of @pool.
 */
int gcip_mem_pool_init(struct gcip_mem_pool *pool, struct device *dev, phys_addr_t base_paddr,
		       size_t size, size_t granule);
/*
 * Releases resources of @pool.
 *
 * Note: you must release (by calling gcip_mem_pool_free) all allocations before calling this
 * function.
 */
void gcip_mem_pool_exit(struct gcip_mem_pool *pool);

/*
 * Allocates and returns the allocated physical address.
 *
 * @size: Size to be allocated.
 *
 * Returns the allocated address. Returns 0 on allocation failure.
 */
phys_addr_t gcip_mem_pool_alloc(struct gcip_mem_pool *pool, size_t size);
/*
 * Returns the address previously allocated by gcip_mem_pool_alloc().
 *
 * The size and address must match what previously passed to / returned by gcip_mem_pool_alloc().
 */
void gcip_mem_pool_free(struct gcip_mem_pool *pool, phys_addr_t paddr, size_t size);

/*
 * Returns the offset between @paddr and @base_paddr passed to gcip_mem_pool_init().
 *
 * @paddr must be a value returned by gcip_mem_pool_alloc().
 */
static inline size_t gcip_mem_pool_offset(struct gcip_mem_pool *pool, phys_addr_t paddr)
{
	return paddr - pool->base_paddr;
}

#endif /* __GCIP_MEM_POOL_H__ */
