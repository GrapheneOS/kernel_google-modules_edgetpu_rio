// SPDX-License-Identifier: GPL-2.0
/*
 * Edge TPU functions for GSX01 SoCs.
 *
 * Copyright (C) 2022 Google LLC
 */

#include <linux/device.h>
#include <linux/gsa/gsa_tpu.h>
#include <linux/types.h>

#include "edgetpu-internal.h"
#include "edgetpu-firmware.h"
#include "edgetpu-mobile-platform.h"
#include "edgetpu-soc.h"
#include "mobile-firmware.h"

#define SSMT_NS_READ_STREAM_VID_OFFSET(n) (0x1000u + (0x4u * (n)))
#define SSMT_NS_WRITE_STREAM_VID_OFFSET(n) (0x1200u + (0x4u * (n)))

#define SSMT_NS_READ_STREAM_VID_REG(base, n)                                   \
	((base) + SSMT_NS_READ_STREAM_VID_OFFSET(n))
#define SSMT_NS_WRITE_STREAM_VID_REG(base, n)                                  \
	((base) + SSMT_NS_WRITE_STREAM_VID_OFFSET(n))

static void gsx01_setup_ssmt(struct edgetpu_dev *etdev)
{
	int i;
	struct edgetpu_mobile_platform_dev *etmdev = to_mobile_dev(etdev);
	struct mobile_image_config *image_config = mobile_firmware_get_image_config(etdev);

	/*
	 * This only works if the SSMT is set to client-driven mode, which only GSA can do.
	 * Skip if GSA is not available
	 */
	if (!etmdev->ssmt_base || !etmdev->gsa_dev)
		return;

	etdev_dbg(etdev, "Setting up SSMT for privilege level: %d\n",
		  image_config->privilege_level);

	/*
	 * Setup non-secure SCIDs, assume VID = SCID when running at TZ or GSA level,
	 * Reset the table to zeroes if running non-secure firmware, since the SSMT
	 * will be in clamped mode and we want all memory accesses to go to the
	 * default page table.
	 *
	 * TODO(b/204384254) Confirm SSMT setup for Rio
	 */
	for (i = 0; i < EDGETPU_NCONTEXTS; i++) {
		int val;

		if (image_config->privilege_level == FW_PRIV_LEVEL_NS)
			val = 0;
		else
			val = i;

		writel(val, SSMT_NS_READ_STREAM_VID_REG(etmdev->ssmt_base, i));
		writel(val, SSMT_NS_WRITE_STREAM_VID_REG(etmdev->ssmt_base, i));
	}
}

int edgetpu_soc_prepare_firmware(struct edgetpu_dev *etdev)
{
	gsx01_setup_ssmt(etdev);
	return 0;
}
