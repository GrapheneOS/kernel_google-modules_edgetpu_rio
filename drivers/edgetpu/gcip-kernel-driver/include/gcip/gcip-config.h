/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Define configuration macros.
 *
 * Copyright (C) 2023 Google LLC
 */

#ifndef __GCIP_CONFIG_H__
#define __GCIP_CONFIG_H__

#define GCIP_IS_GKI (IS_ENABLED(CONFIG_ANDROID) || IS_ENABLED(CONFIG_ANDROID_VENDOR_HOOKS))

/* Macros to check the availability of features and APIs */

/* TODO(b/292499332) Temporary compiler flag to disable vm_flags_set for out-of-date GKIs */
#ifdef GCIP_FORCE_NO_VMA_FLAGS_API
#define GCIP_HAS_VMA_FLAGS_API 0
#else
#define GCIP_HAS_VMA_FLAGS_API                                                                     \
	((LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 25) && GCIP_IS_GKI) ||                        \
	 LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0))
#endif /* GCIP_FORCE_NO_VMA_FLAGS_API */

#define GCIP_HAS_IOMMU_PASID                                                                       \
	((LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0) && GCIP_IS_GKI) ||                         \
	 LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0))

#define GCIP_HAS_AUX_DOMAINS (LINUX_VERSION_CODE <= KERNEL_VERSION(5, 17, 0))

/*
 * TODO(b/277649169) Best fit IOVA allocator was removed in 6.1 GKI
 * The API needs to either be upstreamed, integrated into this driver, or disabled for 6.1
 * compatibility. For now, disable best-fit on all non-Android kernels and any GKI > 5.15.
 */
#define GCIP_HAS_IOVAD_BEST_FIT_ALGO                                                               \
	(LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0) &&                                          \
	 (IS_ENABLED(CONFIG_GCIP_TEST) || GCIP_IS_GKI))

#endif /* __GCIP_CONFIG_H__ */
