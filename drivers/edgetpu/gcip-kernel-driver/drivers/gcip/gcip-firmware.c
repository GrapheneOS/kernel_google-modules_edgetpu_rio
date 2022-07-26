// SPDX-License-Identifier: GPL-2.0
/*
 * GCIP firmware interface.
 *
 * Copyright (C) 2022 Google LLC
 */

#include <gcip/gcip-firmware.h>

char *gcip_fw_flavor_str(enum gcip_fw_flavor fw_flavor)
{
	switch (fw_flavor) {
	case GCIP_FW_FLAVOR_BL1:
		return "stage 2 bootloader";
	case GCIP_FW_FLAVOR_SYSTEST:
		return "test";
	case GCIP_FW_FLAVOR_PROD_DEFAULT:
		return "prod";
	case GCIP_FW_FLAVOR_CUSTOM:
		return "custom";
	case GCIP_FW_FLAVOR_UNKNOWN:
	default:
		return "unknown";
	}
}
