/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * GCIP-integrated IIF driver sync file.
 *
 * Copyright (C) 2023 Google LLC
 */

#ifndef __IIF_IIF_SYNC_FILE_H__
#define __IIF_IIF_SYNC_FILE_H__

#include <linux/file.h>

#include <gcip/iif/iif-fence.h>

/* Sync file which will be exported to the userspace to sync with the fence. */
struct iif_sync_file {
	/* File pointer. */
	struct file *file;
	/* Fence object. */
	struct iif_fence *fence;
};

/* Opens a file which will be exported to the userspace to sync with @fence. */
struct iif_sync_file *iif_sync_file_create(struct iif_fence *fence);

#endif /* __IIF_IIF_SYNC_FILE_H__ */
