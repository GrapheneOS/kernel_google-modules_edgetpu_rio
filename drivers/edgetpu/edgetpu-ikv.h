/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Virtual Inference Interface, implements the protocol between AP kernel and TPU firmware.
 *
 * Copyright (C) 2023 Google LLC
 */
#ifndef __EDGETPU_IKV_H__
#define __EDGETPU_IKV_H__

#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>

#include <gcip/gcip-mailbox.h>

#include "edgetpu-device-group.h"
#include "edgetpu-internal.h"
#include "edgetpu-mailbox.h"

struct edgetpu_ikv_response {
	struct list_head list_entry;
	struct edgetpu_vii_response resp;
	/*
	 * The queue this response will be added to when it has arrived.
	 *
	 * Access to this queue must be protected by `dest_queue_lock`.
	 */
	struct list_head *dest_queue;
	/*
	 * Indicates whether this response has already been handled (either prepared for a client or
	 * marked as timedout).
	 * This flag is used to detect and handle races between response arrival and timeout.
	 *
	 * Accessing this value must be done while holding `dest_queue_lock`.
	 */
	bool processed;
	/*
	 * Lock to synchronize arrival, timeout, and consumption of this response.
	 *
	 * Protects `dest_queue` and `processed`.
	 */
	struct mutex *dest_queue_lock;
	/*
	 * Mailbox awaiter this response was delivered in.
	 * Must be released with `gcip_mailbox_release_awaiter()` after this response has been
	 * processed. Doing so will also free this response.
	 */
	struct gcip_mailbox_resp_awaiter *awaiter;
	/*
	 * Saves the client-provided sequence number so it can be used when returning the response
	 * to the client.
	 *
	 * This is necessary because the command sequence number is overridden with a
	 * Kernel-generated sequence number while in the mailbox queue. This prevents clients from
	 * using conflicting numbers (e.g. Client A and Client B both send commands with seq=3).
	 */
	u64 client_seq;
	/*
	 * A group to notify with the EDGETPU_EVENT_RESPDATA event when this response arrives.
	 */
	struct edgetpu_device_group *group_to_notify;
};

struct edgetpu_ikv {
	struct edgetpu_dev *etdev;

	/* Interface for managing sending/receiving messages via the mailbox queues. */
	struct gcip_mailbox *mbx_protocol;
	/* Interface for accessing the mailbox hardware and the values in their data registers. */
	struct edgetpu_mailbox *mbx_hardware;

	struct edgetpu_coherent_mem cmd_queue_mem;
	struct mutex cmd_queue_lock;
	struct edgetpu_coherent_mem resp_queue_mem;
	spinlock_t resp_queue_lock;

	/* Worker for processing incoming responses */
	struct kthread_worker response_worker;
	struct kthread_work response_work;
	struct task_struct *response_thread;

	/*
	 * Wait queue used by gcip-mailbox for storing pending commands, should the command queue
	 * ever be full. In practice, credit enforcement prevents the queue from ever overflowing.
	 */
	wait_queue_head_t pending_commands;

	/*
	 * Protects the list of pending responses for commands which have already been sent.
	 * The protected list is part of `struct gcip_mailbox`. GCIP code acquires and releases
	 * this lock via the `acquire_wait_list_lock` and `release_wait_list_lock` mailbox ops.
	 */
	struct mutex wait_list_lock;

	/* Whether in-kernel VII is supported. If false, VII is routed through user-space. */
	bool enabled;
};

/*
 * Initializes a VII object.
 *
 * Will request a mailbox from @mgr and allocate cmd/resp queues.
 */
int edgetpu_ikv_init(struct edgetpu_mailbox_manager *mgr, struct edgetpu_ikv *etikv);

/*
 * Re-initializes the initialized VII object.
 *
 * This function is used when the TPU device is reset, it re-programs CSRs related to the VII
 * mailbox.
 *
 * Returns 0 on success, -errno on error.
 */
int edgetpu_ikv_reinit(struct edgetpu_ikv *etikv);

/*
 * Releases resources allocated by @etikv
 *
 * Note: must be invoked after the VII interrupt is disabled and before the @etikv pointer is
 * released.
 */
void edgetpu_ikv_release(struct edgetpu_dev *etdev, struct edgetpu_ikv *etikv);

/*
 * Sends a VII command
 *
 * The command will be executed asynchronously, pushing a pending response into @pending_queue and
 * moving it into @ready_queue when it arrives.
 *
 * @queue_lock will be acquired then released during this call, and will be acquired asynchronously
 * when the response arrives or times-out, so that it can be moved between queues.
 *
 * Before freeing either queue, their owner must first:
 * 1) Set the `processed` flag on all responses in the @pending_queue
 * 2) Release @queue_lock (so the next step can proceed)
 * 3) Cancel all responses in @pending_queue with `gcip_mailbox_cancel_awaiter()`
 * 4) Release all responses in both queues with `gcip_mailbox_release_awaiter()`
 *
 * Returns 0 on success, -errno on error.
 */
int edgetpu_ikv_send_cmd(struct edgetpu_ikv *etikv, struct edgetpu_vii_command *cmd,
			 struct list_head *pending_queue, struct list_head *ready_queue,
			 struct mutex *queue_lock, struct edgetpu_device_group *group_to_notify);

#endif /* __EDGETPU_IKV_H__*/
