/* SPDX-License-Identifier: GPL-2.0 */
/*
 * GCIP Mailbox Ops for the in-kernel VII mailbox
 *
 * Copyright (C) 2023 Google LLC
 */
#ifndef __EDGETPU_IKV_MAILBOX_OPS_H__
#define __EDGETPU_IKV_MAILBOX_OPS_H__

#include <gcip/gcip-mailbox.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>

#include "edgetpu-ikv.h"
#include "edgetpu-mailbox.h"

static inline u32 edgetpu_ikv_get_cmd_queue_head(struct gcip_mailbox *mailbox)
{
	struct edgetpu_ikv *ikv = gcip_mailbox_get_data(mailbox);
	struct edgetpu_mailbox *mbx_hw = ikv->mbx_hardware;

	return EDGETPU_MAILBOX_CMD_QUEUE_READ(mbx_hw, head);
}

static inline u32 edgetpu_ikv_get_cmd_queue_tail(struct gcip_mailbox *mailbox)
{
	struct edgetpu_ikv *ikv = gcip_mailbox_get_data(mailbox);
	struct edgetpu_mailbox *mbx_hw = ikv->mbx_hardware;

	return mbx_hw->cmd_queue_tail;
}

static inline void edgetpu_ikv_inc_cmd_queue_tail(struct gcip_mailbox *mailbox, u32 inc)
{
	struct edgetpu_ikv *ikv = gcip_mailbox_get_data(mailbox);
	struct edgetpu_mailbox *mbx_hw = ikv->mbx_hardware;

	edgetpu_mailbox_inc_cmd_queue_tail(mbx_hw, inc);
}

static int edgetpu_ikv_acquire_cmd_queue_lock(struct gcip_mailbox *mailbox, bool try, bool *atomic)
{
	struct edgetpu_ikv *ikv = gcip_mailbox_get_data(mailbox);

	mutex_lock(&ikv->cmd_queue_lock);
	return 1;
}

static void edgetpu_ikv_release_cmd_queue_lock(struct gcip_mailbox *mailbox)
{
	struct edgetpu_ikv *ikv = gcip_mailbox_get_data(mailbox);

	mutex_unlock(&ikv->cmd_queue_lock);
}

static u64 edgetpu_ikv_get_cmd_elem_seq(struct gcip_mailbox *mailbox, void *cmd)
{
	struct edgetpu_vii_command *vii_cmd = cmd;

	return vii_cmd->seq;
}

static void edgetpu_ikv_set_cmd_elem_seq(struct gcip_mailbox *mailbox, void *cmd, u64 seq)
{
	struct edgetpu_vii_command *vii_cmd = cmd;

	vii_cmd->seq = seq;
}

static u32 edgetpu_ikv_get_cmd_elem_code(struct gcip_mailbox *mailbox, void *cmd)
{
	struct edgetpu_vii_command *vii_cmd = cmd;

	return vii_cmd->code;
}

static inline u32 edgetpu_ikv_get_resp_queue_size(struct gcip_mailbox *mailbox)
{
	struct edgetpu_ikv *ikv = gcip_mailbox_get_data(mailbox);
	struct edgetpu_mailbox *mbx_hw = ikv->mbx_hardware;

	return mbx_hw->resp_queue_size;
}

static inline u32 edgetpu_ikv_get_resp_queue_head(struct gcip_mailbox *mailbox)
{
	struct edgetpu_ikv *ikv = gcip_mailbox_get_data(mailbox);
	struct edgetpu_mailbox *mbx_hw = ikv->mbx_hardware;

	return mbx_hw->resp_queue_head;
}

static inline u32 edgetpu_ikv_get_resp_queue_tail(struct gcip_mailbox *mailbox)
{
	struct edgetpu_ikv *ikv = gcip_mailbox_get_data(mailbox);
	struct edgetpu_mailbox *mbx_hw = ikv->mbx_hardware;

	return EDGETPU_MAILBOX_RESP_QUEUE_READ_SYNC(mbx_hw, tail);
}

static inline void edgetpu_ikv_inc_resp_queue_head(struct gcip_mailbox *mailbox, u32 inc)
{
	struct edgetpu_ikv *ikv = gcip_mailbox_get_data(mailbox);
	struct edgetpu_mailbox *mbx_hw = ikv->mbx_hardware;

	edgetpu_mailbox_inc_resp_queue_head(mbx_hw, inc);
}

static int edgetpu_ikv_acquire_resp_queue_lock(struct gcip_mailbox *mailbox, bool try, bool *atomic)
{
	struct edgetpu_ikv *ikv = gcip_mailbox_get_data(mailbox);

	*atomic = true;

	if (try)
		return spin_trylock_irqsave(&ikv->resp_queue_lock, ikv->resp_queue_lock_flags);

	spin_lock_irqsave(&ikv->resp_queue_lock, ikv->resp_queue_lock_flags);
	return 1;
}

static void edgetpu_ikv_release_resp_queue_lock(struct gcip_mailbox *mailbox)
{
	struct edgetpu_ikv *ikv = gcip_mailbox_get_data(mailbox);

	spin_unlock_irqrestore(&ikv->resp_queue_lock, ikv->resp_queue_lock_flags);
}

static u64 edgetpu_ikv_get_resp_elem_seq(struct gcip_mailbox *mailbox, void *resp)
{
	struct edgetpu_vii_response *vii_resp = resp;

	return vii_resp->seq;
}

static void edgetpu_ikv_set_resp_elem_seq(struct gcip_mailbox *mailbox, void *resp, u64 seq)
{
	struct edgetpu_vii_response *vii_resp = resp;

	vii_resp->seq = seq;
}

static void edgetpu_ikv_acquire_wait_list_lock(struct gcip_mailbox *mailbox, bool irqsave,
					       unsigned long *flags)
{
	struct edgetpu_ikv *ikv = gcip_mailbox_get_data(mailbox);

	spin_lock_irqsave(&ikv->wait_list_lock, *flags);
}

static void edgetpu_ikv_release_wait_list_lock(struct gcip_mailbox *mailbox, bool irqrestore,
					       unsigned long flags)
{
	struct edgetpu_ikv *ikv = gcip_mailbox_get_data(mailbox);

	spin_unlock_irqrestore(&ikv->wait_list_lock, flags);
}

static int edgetpu_ikv_wait_for_cmd_queue_not_full(struct gcip_mailbox *mailbox)
{
	struct edgetpu_ikv *ikv = gcip_mailbox_get_data(mailbox);
	u32 tail = mailbox->ops->get_cmd_queue_tail(mailbox);
	int ret;

	if (mailbox->ops->get_cmd_queue_head(mailbox) != (tail ^ mailbox->queue_wrap_bit))
		return 0;

	/* Credit enforcement should prevent this from ever happening. Log an error. */
	etdev_warn_ratelimited(ikv->etdev, "kernel VII command queue full\n");

	ret = wait_event_timeout(ikv->pending_commands,
				 mailbox->ops->get_cmd_queue_head(mailbox) !=
					 (tail ^ mailbox->queue_wrap_bit),
				 msecs_to_jiffies(mailbox->timeout));
	if (!ret)
		return -ETIMEDOUT;

	return 0;
}

static int edgetpu_ikv_before_enqueue_wait_list(struct gcip_mailbox *mailbox, void *resp,
						struct gcip_mailbox_resp_awaiter *awaiter)
{
	struct edgetpu_ikv_response *ikv_resp;

	/*
	 * Save the awaiter inside the response, so it can be cleaned up on response arrival,
	 * time-out, or free due to owning device-group closing.
	 *
	 * Since awaiters are only NULL for synchronous commands (which in-kernel VII does not
	 * support), there's no need to check it.
	 */
	ikv_resp = awaiter->data;
	ikv_resp->awaiter = awaiter;

	return 0;
}

static int edgetpu_ikv_after_enqueue_cmd(struct gcip_mailbox *mailbox, void *cmd)
{
	struct edgetpu_ikv *ikv = gcip_mailbox_get_data(mailbox);

	EDGETPU_MAILBOX_CMD_QUEUE_WRITE_SYNC(ikv->mbx_hardware, doorbell_set, 1);

	return 0;
}

static void edgetpu_ikv_after_fetch_resps(struct gcip_mailbox *mailbox, u32 num_resps)
{
	struct edgetpu_ikv *ikv = gcip_mailbox_get_data(mailbox);
	u32 size = mailbox->ops->get_resp_queue_size(mailbox);
	/*
	 * We consumed a lot of responses - ring the doorbell of *cmd* queue to notify the firmware,
	 * which might be waiting us to consume the response queue.
	 */
	if (num_resps >= size / 2)
		EDGETPU_MAILBOX_CMD_QUEUE_WRITE(ikv->mbx_hardware, doorbell_set, 1);
}

static void edgetpu_ikv_handle_awaiter_arrived(struct gcip_mailbox *mailbox,
					       struct gcip_mailbox_resp_awaiter *awaiter)
{
	struct edgetpu_ikv_response *resp = awaiter->data;
	unsigned long flags;

	spin_lock_irqsave(resp->dest_queue_lock, flags);

	/*
	 * Return immediately if either of the following caused the response to be "processed":
	 * - the response timed-out
	 * - the queue waiting for the response is being released
	 */
	if (resp->processed)
		goto out;
	resp->processed = true;

	/* TODO(johnscheible) reject and free responses with incorrect `client_id` */

	/* Move the response from the "pending" list to the "ready" list */
	list_del(&resp->list_entry);
	list_add_tail(&resp->list_entry, resp->dest_queue);

	/* Set the response sequence number to the value expected by the client. */
	resp->resp.seq = resp->client_seq;

	if (resp->group_to_notify) {
		resp->group_to_notify->available_vii_credits++;
		edgetpu_group_notify(resp->group_to_notify, EDGETPU_EVENT_RESPDATA);
	}

out:
	spin_unlock_irqrestore(resp->dest_queue_lock, flags);
}

static void edgetpu_ikv_handle_awaiter_timedout(struct gcip_mailbox *mailbox,
						struct gcip_mailbox_resp_awaiter *awaiter)
{
	struct edgetpu_ikv *ikv = gcip_mailbox_get_data(mailbox);
	struct edgetpu_ikv_response *resp = awaiter->data;
	/* Store an independent pointer to `dest_queue_lock`, since `resp` may be released. */
	spinlock_t *dest_queue_lock = resp->dest_queue_lock;
	unsigned long flags;

	etdev_warn(ikv->etdev, "IKV seq %llu timed out", resp->client_seq);
	spin_lock_irqsave(dest_queue_lock, flags);

	/*
	 * Return immediately if either of the following caused the response to be "processed":
	 * - the response timed-out
	 * - the queue waiting for the response is being released
	 */
	if (resp->processed)
		goto out;
	resp->processed = true;

	/* TODO(johnscheible) Currently, VII doesn't have a "timedout" concept, so just delete it */
	list_del(&resp->list_entry);
	gcip_mailbox_release_awaiter(awaiter);

	if (resp->group_to_notify) {
		resp->group_to_notify->available_vii_credits++;
		edgetpu_group_notify(resp->group_to_notify, EDGETPU_EVENT_RESPDATA);
	}

out:
	spin_unlock_irqrestore(dest_queue_lock, flags);
}

static void edgetpu_ikv_flush_awaiter(struct gcip_mailbox *mailbox,
				      struct gcip_mailbox_resp_awaiter *awaiter)
{
	struct edgetpu_ikv_response *resp = awaiter->data;
	/* Store an independent pointer to `dest_queue_lock`, since `resp` may be released. */
	spinlock_t *dest_queue_lock = resp->dest_queue_lock;
	unsigned long flags;

	spin_lock_irqsave(dest_queue_lock, flags);

	if (resp->processed)
		goto out;
	resp->processed = true;

	/*
	 * If the IKV mailbox is being released, the device_groups should be getting released too.
	 * Just to be thorough, refund the credit.
	 */
	if (resp->group_to_notify)
		resp->group_to_notify->available_vii_credits++;

	gcip_mailbox_release_awaiter(awaiter);

out:
	spin_unlock_irqrestore(dest_queue_lock, flags);
}

static void edgetpu_ikv_release_awaiter_data(void *data)
{
	struct edgetpu_ikv_response *resp = data;

	kfree(resp);
}

static const struct gcip_mailbox_ops ikv_mailbox_ops = {
	.get_cmd_queue_head = edgetpu_ikv_get_cmd_queue_head,
	.get_cmd_queue_tail = edgetpu_ikv_get_cmd_queue_tail,
	.inc_cmd_queue_tail = edgetpu_ikv_inc_cmd_queue_tail,
	.acquire_cmd_queue_lock = edgetpu_ikv_acquire_cmd_queue_lock,
	.release_cmd_queue_lock = edgetpu_ikv_release_cmd_queue_lock,
	.get_cmd_elem_seq = edgetpu_ikv_get_cmd_elem_seq,
	.set_cmd_elem_seq = edgetpu_ikv_set_cmd_elem_seq,
	.get_cmd_elem_code = edgetpu_ikv_get_cmd_elem_code,
	.get_resp_queue_size = edgetpu_ikv_get_resp_queue_size,
	.get_resp_queue_head = edgetpu_ikv_get_resp_queue_head,
	.get_resp_queue_tail = edgetpu_ikv_get_resp_queue_tail,
	.inc_resp_queue_head = edgetpu_ikv_inc_resp_queue_head,
	.acquire_resp_queue_lock = edgetpu_ikv_acquire_resp_queue_lock,
	.release_resp_queue_lock = edgetpu_ikv_release_resp_queue_lock,
	.get_resp_elem_seq = edgetpu_ikv_get_resp_elem_seq,
	.set_resp_elem_seq = edgetpu_ikv_set_resp_elem_seq,
	.acquire_wait_list_lock = edgetpu_ikv_acquire_wait_list_lock,
	.release_wait_list_lock = edgetpu_ikv_release_wait_list_lock,
	.wait_for_cmd_queue_not_full = edgetpu_ikv_wait_for_cmd_queue_not_full,
	.before_enqueue_wait_list = edgetpu_ikv_before_enqueue_wait_list,
	.after_enqueue_cmd = edgetpu_ikv_after_enqueue_cmd,
	.after_fetch_resps = edgetpu_ikv_after_fetch_resps,
	/* .before_handle_resp is not needed */
	.handle_awaiter_arrived = edgetpu_ikv_handle_awaiter_arrived,
	.handle_awaiter_timedout = edgetpu_ikv_handle_awaiter_timedout,
	.flush_awaiter = edgetpu_ikv_flush_awaiter,
	.release_awaiter_data = edgetpu_ikv_release_awaiter_data,
};

#endif /* __EDGETPU_IKV_MAILBOX_OPS_H__ */
