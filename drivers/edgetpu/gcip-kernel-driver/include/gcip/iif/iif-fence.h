/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * GCIP-integrated IIF driver fence.
 *
 * Copyright (C) 2023 Google LLC
 */

#ifndef __IIF_IIF_FENCE_H__
#define __IIF_IIF_FENCE_H__

#include <linux/kref.h>

#include <gcip/iif/iif-manager.h>
#include <gcip/iif/iif.h>

struct iif_fence_ops;

/* The fence object. */
struct iif_fence {
	/* IIF manager. */
	struct iif_manager *mgr;
	/* Fence ID. */
	int id;
	/* The number of total signalers to be submitted. */
	unsigned int total_signalers;
	/* Reference count. */
	struct kref kref;
	/* Operators. */
	const struct iif_fence_ops *ops;
};

/* Operators of `struct iif_fence`. */
struct iif_fence_ops {
	/*
	 * Called on destruction of @fence to release additional resources when its reference count
	 * becomes zero.
	 *
	 * This callback is optional.
	 * Context: normal and in_interrupt().
	 */
	void (*on_release)(struct iif_fence *fence);
};

/*
 * Initializes @fence which will be signaled by @signaler_ip IP. @total_signalers is the number of
 * signalers which must be submitted to the fence. Its initial reference count is 1.
 *
 * The initialized fence will be assigned an ID which depends on @signaler_ip. Each IP will have at
 * most `IIF_NUM_FENCES_PER_IP` number of fences and the assigned fence ID for IP[i] will be one of
 * [i * IIF_NUM_FENCES_PER_IP ~ (i + 1) * IIF_NUM_FENCES_PER_IP - 1].
 */
int iif_fence_init(struct iif_manager *mgr, struct iif_fence *fence,
		   const struct iif_fence_ops *ops, enum iif_ip_type signaler_ip,
		   unsigned int total_signalers);

/* Increases the reference count of @fence. */
struct iif_fence *iif_fence_get(struct iif_fence *fence);

/* Decreases the reference count of @fence and if it becomes 0, releases @fence. */
void iif_fence_put(struct iif_fence *fence);

#endif /* __IIF_IIF_FENCE_H__ */
