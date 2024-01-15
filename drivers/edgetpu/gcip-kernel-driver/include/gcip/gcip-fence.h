/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Abstracted interface for fences.
 *
 * Copyright (C) 2023 Google LLC
 */

#ifndef __GCIP_FENCE_H__
#define __GCIP_FENCE_H__

#include <linux/dma-fence.h>
#include <linux/kref.h>

#include <gcip/iif/iif-fence.h>
#include <gcip/iif/iif-manager.h>
#include <gcip/iif/iif.h>

#define GCIP_FENCE_REMAINING_SIGNALERS_NO_REGISTER_EVENTFD (~0u)

struct gcip_fence;
struct gcip_fence_ops;
struct gcip_fence_all_signaler_submitted_cb;

/* The callback which will be called when all signalers have been submitted to @fence. */
typedef void (*gcip_fence_all_signaler_submitted_cb_t)(
	struct gcip_fence *fence, struct gcip_fence_all_signaler_submitted_cb *cb);

enum gcip_fence_type {
	GCIP_INTER_IP_FENCE,
	GCIP_IN_KERNEL_FENCE,
};

/* Abstracted fence structure. */
struct gcip_fence {
	union {
		struct iif_fence *iif;
		struct dma_fence *ikf;
	} fence;
	/* The type of fence. */
	enum gcip_fence_type type;
	/* Reference count. */
	struct kref kref;
};

/* Abstracted all signaler submitted callback structure. */
struct gcip_fence_all_signaler_submitted_cb {
	/* IIF callback instance. */
	struct iif_fence_all_signaler_submitted_cb iif_cb;
	/* The actual callback function. */
	gcip_fence_all_signaler_submitted_cb_t func;
	/* Fence object. */
	struct gcip_fence *fence;
};

/*
 * Creates an IIF fence and bind a file descriptor to it.
 *
 * Returns the fd of the fence on success. Otherwise, returns a negative errno.
 */
int gcip_fence_create_iif(struct iif_manager *mgr, enum iif_ip_type signaler_ip,
			  unsigned int total_signalers);

/*
 * Gets a fence from @fd and increments its reference count.
 *
 * Returns the fence pointer on success. Otherwise, returns an error pointer.
 */
struct gcip_fence *gcip_fence_fdget(int fd);

/* Increments the reference count of @fence. */
struct gcip_fence *gcip_fence_get(struct gcip_fence *fence);

/* Puts the fence and decrements its reference count. */
void gcip_fence_put(struct gcip_fence *fence);

/*
 * Submits a signaler.
 *
 * This function is only meaningful when the fence type is GCIP_INTER_IP_FENCE.
 *
 * Returns 0 if the submission succeeds. Otherwise, returns a negative errno.
 */
int gcip_fence_submit_signaler(struct gcip_fence *fence);

/*
 * Submits a waiter.
 * Note that the waiter submission will not be done when not all signalers have been submitted.
 *
 * This function is only meaningful when the fence type is GCIP_INTER_IP_FENCE.
 *
 * Returns the number of remaining signalers to be submitted. (i.e., the submission actually
 * has been succeeded when the function returns 0.) Otherwise, returns a negative errno if it fails
 * with other reasons.
 */
int gcip_fence_submit_waiter(struct gcip_fence *fence);

/*
 * Signals @fence. If all signalers have signaled the fence, it will notify polling FDs.
 *
 * If @fence is going to signaled with an error, one can pass @errno to let @fence notice it.
 */
void gcip_fence_signal(struct gcip_fence *fence, int errno);

/*
 * Notifies @fence that a command which waited the fence has finished their work.
 *
 * This function is only meaningful when the fence type is GCIP_INTER_IP_FENCE.
 */
void gcip_fence_waited(struct gcip_fence *fence);

/*
 * Registers a callback which will be called when all signalers are submitted for @fence and
 * returns the number of remaining signalers to be submitted to @cb->remaining_signalers. Once the
 * callback is called, it will be automatically unregistered from @fence.
 *
 * This function is only meaningful when the fence type is GCIP_INTER_IP_FENCE.
 *
 * Returns 0 if succeeded. If all signalers are already submitted, returns -EPERM.
 */
int gcip_fence_add_all_signaler_submitted_cb(struct gcip_fence *fence,
					     struct gcip_fence_all_signaler_submitted_cb *cb,
					     gcip_fence_all_signaler_submitted_cb_t func);

/*
 * Unregisters the callback which is registered by the callback above. Calling this function with
 * @cb which has never been added will cause unexpected action.
 *
 * This function is only meaningful when the fence type is GCIP_INTER_IP_FENCE.
 *
 * Returns true if the callback is removed before its being called.
 */
bool gcip_fence_remove_all_signaler_submitted_cb(struct gcip_fence *fence,
						 struct gcip_fence_all_signaler_submitted_cb *cb);

/* Returns the ID of @fence if @fence is IIF. Otherwise, returns -EINVAL. */
int gcip_fence_get_iif_id(struct gcip_fence *fence);

/*
 * Waits on @fences to complete the signaler submission. If at least one of @fences have remaining
 * signalers to be submitted, it will register @eventfd and will trigger it once all fences have
 * finishes the submission. Also, the number of remaining signalers of each fence will be returned
 * to @remaining_signalers in the same order with @fences.
 *
 * If @eventfd is `GCIP_FENCE_REMAINING_SIGNALERS_NO_REGISTER_EVENTFD`, this function won't wait on
 * @fences to finish signaler submission and will simply return the number of remaining signalers of
 * each fence.
 *
 * This function is only meaningful when fences are IIF.
 *
 * Returns 0 on success. Otherwise, returns a negative errno.
 */
int gcip_fence_wait_signaler_submission(struct gcip_fence **fences, int num_fences,
					unsigned int eventfd, int *remaining_signalers);
/*
 * Returns the signal completion status of @fence.
 *
 * Returns 0 if the fence has not yet been signaled, 1 if the fence has been signaled without an
 * error condition, or a negative error code if the fence has been completed in err.
 */
int gcip_fence_get_status(struct gcip_fence *fence);

#endif /* __GCIP_FENCE_H__ */