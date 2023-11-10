// SPDX-License-Identifier: GPL-2.0-only
/*
 * GCIP-integrated IIF driver sync file.
 *
 * Copyright (C) 2023 Google LLC
 */

#include <linux/anon_inodes.h>
#include <linux/bitops.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/types.h>

#include <gcip/iif/iif-fence.h>
#include <gcip/iif/iif-sync-file.h>

static void iif_sync_file_fence_signaled(struct iif_fence *fence, struct iif_fence_poll_cb *poll_cb)
{
	struct iif_sync_file *sync_file = container_of(poll_cb, struct iif_sync_file, poll_cb);

	wake_up_all(&sync_file->wq);
}

static int iif_sync_file_release(struct inode *inode, struct file *file)
{
	struct iif_sync_file *sync_file = file->private_data;

	iif_fence_on_sync_file_release(sync_file->fence);
	if (test_bit(IIF_SYNC_FILE_FLAGS_POLL_ENABLED, &sync_file->flags))
		iif_fence_remove_poll_callback(sync_file->fence, &sync_file->poll_cb);
	iif_fence_put(sync_file->fence);
	kfree(sync_file);

	return 0;
}

static __poll_t iif_sync_file_poll(struct file *file, poll_table *wait)
{
	struct iif_sync_file *sync_file = file->private_data;
	int ret;

	poll_wait(file, &sync_file->wq, wait);

	if (list_empty(&sync_file->poll_cb.node) &&
	    !test_and_set_bit(IIF_SYNC_FILE_FLAGS_POLL_ENABLED, &sync_file->flags)) {
		ret = iif_fence_add_poll_callback(sync_file->fence, &sync_file->poll_cb,
						  iif_sync_file_fence_signaled);
		/* If all signalers of the fence already signaled, just wake up all. */
		if (ret < 0)
			wake_up_all(&sync_file->wq);
	}

	return iif_fence_is_signaled(sync_file->fence) ? EPOLLIN : 0;
}

static const struct file_operations iif_sync_file_fops = {
	.release = iif_sync_file_release,
	.poll = iif_sync_file_poll,
};

struct iif_sync_file *iif_sync_file_create(struct iif_fence *fence)
{
	struct iif_sync_file *sync_file;
	int ret;

	sync_file = kzalloc(sizeof(*sync_file), GFP_KERNEL);
	if (!sync_file)
		return ERR_PTR(-ENOMEM);

	sync_file->file = anon_inode_getfile("iif_file", &iif_sync_file_fops, sync_file, 0);
	if (IS_ERR(sync_file->file)) {
		ret = PTR_ERR(sync_file->file);
		goto err_free_sync_file;
	}

	sync_file->fence = iif_fence_get(fence);

	init_waitqueue_head(&sync_file->wq);
	INIT_LIST_HEAD(&sync_file->poll_cb.node);

	return sync_file;

err_free_sync_file:
	kfree(sync_file);
	return ERR_PTR(ret);
}

struct iif_sync_file *iif_sync_file_fdget(int fd)
{
	struct file *file = fget(fd);

	if (!file)
		return ERR_PTR(-EBADF);

	if (file->f_op != &iif_sync_file_fops) {
		fput(file);
		return ERR_PTR(-EINVAL);
	}

	return file->private_data;
}
