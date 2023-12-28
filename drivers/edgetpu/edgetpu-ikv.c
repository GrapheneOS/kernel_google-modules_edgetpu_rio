// SPDX-License-Identifier: GPL-2.0
/*
 * Virtual Inference Interface, implements the protocol between AP kernel and TPU firmware.
 *
 * Copyright (C) 2023 Google LLC
 */

#include <gcip/gcip-mailbox.h>
#include <linux/slab.h>

#include "edgetpu-ikv.h"
#include "edgetpu-ikv-mailbox-ops.h"
#include "edgetpu-iremap-pool.h"
#include "edgetpu-mailbox.h"
#include "edgetpu.h"

/* size of queue for in-kernel VII  mailbox */
#define QUEUE_SIZE CIRC_QUEUE_MAX_SIZE(CIRC_QUEUE_WRAP_BIT)

#ifdef EDGETPU_IKV_TIMEOUT
#define IKV_TIMEOUT	EDGETPU_IKV_TIMEOUT
#elif IS_ENABLED(CONFIG_EDGETPU_TEST)
/* fake-firmware could respond in a short time */
#define IKV_TIMEOUT	(200)
#else
/* Wait for up to 20 second for FW to respond. */
#define IKV_TIMEOUT	(20000)
#endif

static void edgetpu_ikv_handle_irq(struct edgetpu_mailbox *mailbox)
{
	struct edgetpu_ikv *ikv = mailbox->internal.etikv;

	/*
	 * Process responses directly, to avoid the latency from scheduling a worker thread.
	 *
	 * Since the in-kernel VII `acquire_resp_queue_lock` op sets @atomic to true, the response
	 * processing function will be safe to call in an IRQ context.
	 */
	/* TODO(b/312098074) Rename this function to indicate it is not only called by workers */
	gcip_mailbox_consume_responses_work(ikv->mbx_protocol);
}

static int edgetpu_ikv_alloc_queue(struct edgetpu_ikv *etikv, enum gcip_mailbox_queue_type type)
{
	struct edgetpu_dev *etdev = etikv->etdev;
	u32 size;
	struct edgetpu_coherent_mem *mem;
	int ret;

	switch (type) {
	case GCIP_MAILBOX_CMD_QUEUE:
		size = QUEUE_SIZE * sizeof(struct edgetpu_vii_command);
		mem = &etikv->cmd_queue_mem;
		break;
	case GCIP_MAILBOX_RESP_QUEUE:
		size = QUEUE_SIZE * sizeof(struct edgetpu_vii_response);
		mem = &etikv->resp_queue_mem;
		break;
	}

	/*
	 * in-kernel VII is kernel-to-firmware communication, so its queues are allocated in the
	 * same context as KCI, despite being a separate protocol.
	 */
	ret = edgetpu_iremap_alloc(etdev, size,  mem);
	if (ret)
		return ret;

	ret = edgetpu_mailbox_set_queue(etikv->mbx_hardware, type, mem->tpu_addr, QUEUE_SIZE);
	if (ret) {
		etdev_err(etikv->etdev, "failed to set mailbox queue: %d", ret);
		edgetpu_iremap_free(etdev, mem);
		return ret;
	}

	return 0;
}

static void edgetpu_ikv_free_queue(struct edgetpu_ikv *etikv, enum gcip_mailbox_queue_type type)
{
	struct edgetpu_dev *etdev = etikv->etdev;

	switch (type) {
	case GCIP_MAILBOX_CMD_QUEUE:
		edgetpu_iremap_free(etdev, &etikv->cmd_queue_mem);
		break;
	case GCIP_MAILBOX_RESP_QUEUE:
		edgetpu_iremap_free(etdev, &etikv->resp_queue_mem);
		break;
	}
}

int edgetpu_ikv_init(struct edgetpu_mailbox_manager *mgr, struct edgetpu_ikv *etikv)
{
	struct edgetpu_mailbox *mbx_hardware;
	struct gcip_mailbox_args args = {
		.dev = mgr->etdev->dev,
		.queue_wrap_bit = CIRC_QUEUE_WRAP_BIT,
		.cmd_elem_size = sizeof(struct edgetpu_vii_command),
		.resp_elem_size = sizeof(struct edgetpu_vii_response),
		.timeout = IKV_TIMEOUT,
		.ops = &ikv_mailbox_ops,
		.data = etikv,
	};
	int ret;

	etikv->etdev = mgr->etdev;
	etikv->enabled = mgr->use_ikv;
	if (!etikv->enabled)
		return 0;

	mbx_hardware = edgetpu_mailbox_ikv(mgr);
	if (IS_ERR_OR_NULL(mbx_hardware))
		return !mbx_hardware ? -ENODEV : PTR_ERR(mbx_hardware);
	mbx_hardware->handle_irq = edgetpu_ikv_handle_irq;
	mbx_hardware->internal.etikv = etikv;
	etikv->mbx_hardware = mbx_hardware;

	etikv->mbx_protocol =
		devm_kzalloc(mgr->etdev->dev, sizeof(*etikv->mbx_protocol), GFP_KERNEL);
	if (!etikv->mbx_protocol) {
		ret = -ENOMEM;
		goto err_mailbox_remove;
	}

	ret = edgetpu_ikv_alloc_queue(etikv, GCIP_MAILBOX_CMD_QUEUE);
	if (ret)
		goto err_mailbox_remove;
	mutex_init(&etikv->cmd_queue_lock);

	ret = edgetpu_ikv_alloc_queue(etikv, GCIP_MAILBOX_RESP_QUEUE);
	if (ret)
		goto err_free_cmd_queue;
	spin_lock_init(&etikv->resp_queue_lock);

	args.cmd_queue = etikv->cmd_queue_mem.vaddr;
	args.resp_queue = etikv->resp_queue_mem.vaddr;
	ret = gcip_mailbox_init(etikv->mbx_protocol, &args);
	if (ret)
		goto err_free_resp_queue;

	init_waitqueue_head(&etikv->pending_commands);
	spin_lock_init(&etikv->wait_list_lock);

	edgetpu_mailbox_enable(mbx_hardware);

	return 0;

err_free_resp_queue:
	edgetpu_ikv_free_queue(etikv, GCIP_MAILBOX_RESP_QUEUE);
err_free_cmd_queue:
	edgetpu_ikv_free_queue(etikv, GCIP_MAILBOX_CMD_QUEUE);
err_mailbox_remove:
	edgetpu_mailbox_remove(mgr, mbx_hardware);
	etikv->mbx_hardware = NULL;

	return ret;
}

int edgetpu_ikv_reinit(struct edgetpu_ikv *etikv)
{
	struct edgetpu_mailbox *mbx_hardware = etikv->mbx_hardware;
	struct edgetpu_mailbox_manager *mgr;
	struct edgetpu_coherent_mem *cmd_queue_mem = &etikv->cmd_queue_mem;
	struct edgetpu_coherent_mem *resp_queue_mem = &etikv->resp_queue_mem;
	unsigned long flags;
	int ret;

	/*
	 * If in-kernel VII is enabled, mailbox hardware is guaranteed to be present, otherwise if
	 * not enabled, there's nothing to re-initialize.
	 */
	if (!etikv->enabled)
		return 0;

	ret = edgetpu_mailbox_set_queue(mbx_hardware, GCIP_MAILBOX_CMD_QUEUE,
					cmd_queue_mem->tpu_addr, QUEUE_SIZE);
	if (ret)
		return ret;

	ret = edgetpu_mailbox_set_queue(mbx_hardware, GCIP_MAILBOX_RESP_QUEUE,
					resp_queue_mem->tpu_addr, QUEUE_SIZE);
	if (ret)
		return ret;

	mgr = etikv->etdev->mailbox_manager;
	/* Restore irq handler */
	write_lock_irqsave(&mgr->mailboxes_lock, flags);
	mbx_hardware->handle_irq = edgetpu_ikv_handle_irq;
	write_unlock_irqrestore(&mgr->mailboxes_lock, flags);

	edgetpu_mailbox_init_doorbells(mbx_hardware);
	edgetpu_mailbox_enable(mbx_hardware);

	return 0;
}

void edgetpu_ikv_release(struct edgetpu_dev *etdev, struct edgetpu_ikv *etikv)
{
	struct edgetpu_mailbox_manager *mgr;
	struct edgetpu_mailbox *mbx_hardware;
	unsigned long flags;

	if (!etikv || !etikv->enabled)
		return;

	mbx_hardware = etikv->mbx_hardware;
	if (mbx_hardware) {
		mgr = etikv->etdev->mailbox_manager;
		/* Remove IRQ handler to stop responding to interrupts */
		write_lock_irqsave(&mgr->mailboxes_lock, flags);
		mbx_hardware->handle_irq = NULL;
		write_unlock_irqrestore(&mgr->mailboxes_lock, flags);
	}

	gcip_mailbox_release(etikv->mbx_protocol);
	etikv->mbx_hardware = NULL;

	edgetpu_ikv_free_queue(etikv, GCIP_MAILBOX_CMD_QUEUE);
	edgetpu_ikv_free_queue(etikv, GCIP_MAILBOX_RESP_QUEUE);
}

int edgetpu_ikv_send_cmd(struct edgetpu_ikv *etikv, struct edgetpu_vii_command *cmd,
			 struct list_head *pending_queue, struct list_head *ready_queue,
			 spinlock_t *queue_lock, struct edgetpu_device_group *group_to_notify)
{
	struct edgetpu_ikv_response *resp;
	struct gcip_mailbox_resp_awaiter *awaiter;
	unsigned long flags;
	int ret;

	if (!etikv->enabled)
		return -ENODEV;

	/* TODO(johnscheible) check and consume credit here */

	resp = kzalloc(sizeof(*resp), GFP_KERNEL);
	if (!resp) {
		ret = -ENOMEM;
		goto err_refund_credit;
	}

	resp->dest_queue = ready_queue;
	resp->dest_queue_lock = queue_lock;
	resp->processed = false;
	resp->client_seq = cmd->seq;
	resp->group_to_notify = group_to_notify;
	spin_lock_irqsave(queue_lock, flags);
	list_add_tail(&resp->list_entry, pending_queue);
	spin_unlock_irqrestore(queue_lock, flags);

	awaiter = gcip_mailbox_put_cmd(etikv->mbx_protocol, cmd, &resp->resp, resp);
	if (IS_ERR(awaiter)) {
		ret = PTR_ERR(awaiter);
		goto err_free_resp;
	}

	return 0;

err_free_resp:
	list_del(&resp->list_entry);
	kfree(resp);
err_refund_credit:
	/* TODO(johnscheible) release credit */
	return ret;
}
