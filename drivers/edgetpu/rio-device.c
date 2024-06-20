// SPDX-License-Identifier: GPL-2.0
/*
 * Rio Edge TPU ML accelerator device host support.
 *
 * Copyright (C) 2021 Google, Inc.
 */

#include <linux/types.h>

#include "edgetpu-config.h"
#include "edgetpu-internal.h"
#include "edgetpu-mailbox.h"

int edgetpu_chip_get_ext_mailbox_index(u32 mbox_type, u32 *start, u32 *end)
{
	switch (mbox_type) {
	case EDGETPU_EXTERNAL_MAILBOX_TYPE_DSP:
		*start = RIO_EXT_DSP_MAILBOX_START;
		*end = RIO_EXT_DSP_MAILBOX_END;
		return 0;
	default:
		return -ENOENT;
	}
}
