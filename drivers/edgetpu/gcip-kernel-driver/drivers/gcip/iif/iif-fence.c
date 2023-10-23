// SPDX-License-Identifier: GPL-2.0-only
/*
 * GCIP-integrated IIF driver fence.
 *
 * Copyright (C) 2023 Google LLC
 */

#include <linux/idr.h>
#include <linux/kref.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 16, 0)
#include <linux/container_of.h>
#endif

#include <gcip/iif/iif-fence.h>
#include <gcip/iif/iif-manager.h>
#include <gcip/iif/iif.h>

/* Cleans up @fence which was initialized by the `iif_fence_init` function. */
static void iif_fence_destroy(struct kref *kref)
{
	struct iif_fence *fence = container_of(kref, struct iif_fence, kref);

	ida_free(&fence->mgr->idp, fence->id);

	if (fence->ops && fence->ops->on_release)
		fence->ops->on_release(fence);
}

int iif_fence_init(struct iif_manager *mgr, struct iif_fence *fence,
		   const struct iif_fence_ops *ops, enum iif_ip_type signaler_ip,
		   unsigned int total_signalers)
{
	unsigned int id_min = signaler_ip * IIF_NUM_FENCES_PER_IP,
		     id_max = id_min + IIF_NUM_FENCES_PER_IP - 1;

	fence->id = ida_alloc_range(&mgr->idp, id_min, id_max, GFP_KERNEL);
	if (fence->id < 0)
		return fence->id;

	fence->mgr = mgr;
	fence->total_signalers = total_signalers;
	fence->ops = ops;
	kref_init(&fence->kref);

	return 0;
}

struct iif_fence *iif_fence_get(struct iif_fence *fence)
{
	if (fence)
		kref_get(&fence->kref);
	return fence;
}

void iif_fence_put(struct iif_fence *fence)
{
	if (fence)
		kref_put(&fence->kref, iif_fence_destroy);
}
