// SPDX-License-Identifier: GPL-2.0-only
/*
 * GCIP-integrated IIF driver sync file.
 *
 * Copyright (C) 2023 Google LLC
 */

#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h>

#include <gcip/iif/iif-fence.h>
#include <gcip/iif/iif-sync-file.h>

static int iif_sync_file_release(struct inode *inode, struct file *file)
{
	struct iif_sync_file *sync_file = file->private_data;

	iif_fence_put(sync_file->fence);
	kfree(sync_file);

	return 0;
}

static const struct file_operations iif_sync_file_fops = {
	.release = iif_sync_file_release,
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

	return sync_file;

err_free_sync_file:
	kfree(sync_file);
	return ERR_PTR(ret);
}
