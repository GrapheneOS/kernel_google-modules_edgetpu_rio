/* SPDX-License-Identifier: GPL-2.0 */
/*
 * GCIP firmware interface.
 *
 * Copyright (C) 2022 Google LLC
 */

#ifndef __GCIP_FIRMWARE_H__
#define __GCIP_FIRMWARE_H__

#include <linux/types.h>

enum gcip_fw_status {
	/* No firmware loaded yet, or last firmware failed to run. */
	GCIP_FW_INVALID = 0,
	/* Load in progress. */
	GCIP_FW_LOADING = 1,
	/* Current firmware is valid and can be restarted. */
	GCIP_FW_VALID = 2,
};

/* Firmware flavors returned via KCI FIRMWARE_INFO command. */
enum gcip_fw_flavor {
	/* Unused value for extending enum storage type. */
	GCIP_FW_FLAVOR_ERROR = -1,
	/* Used by host when cannot determine the flavor. */
	GCIP_FW_FLAVOR_UNKNOWN = 0,
	/* Second-stage bootloader (no longer used). */
	GCIP_FW_FLAVOR_BL1 = 1,
	/* Systest app image. */
	GCIP_FW_FLAVOR_SYSTEST = 2,
	/* Default production app image. */
	GCIP_FW_FLAVOR_PROD_DEFAULT = 3,
	/* Custom image produced by other teams. */
	GCIP_FW_FLAVOR_CUSTOM = 4,
};

/* Type of firmware crash which will be sent by GCIP_RKCI_FIRMWARE_CRASH RKCI command. */
enum gcip_fw_crash_type {
	/* Assert happened. */
	GCIP_FW_CRASH_ASSERT_FAIL = 0,
	/* Data abort exception. */
	GCIP_FW_CRASH_DATA_ABORT = 1,
	/* Prefetch abort exception. */
	GCIP_FW_CRASH_PREFETCH_ABORT = 2,
	/* Undefined exception. */
	GCIP_FW_CRASH_UNDEFINED_EXCEPTION = 3,
	/* Exception which cannot be recovered by the firmware itself. */
	GCIP_FW_CRASH_UNRECOVERABLE_FAULT = 4,
	/* Used in debug dump. */
	GCIP_FW_CRASH_DUMMY_CRASH_TYPE = 0xFF,
};

/* Firmware info filled out via KCI FIRMWARE_INFO command. */
struct gcip_fw_info {
	uint64_t fw_build_time; /* BuildData::Timestamp() */
	uint32_t fw_flavor; /* enum gcip_fw_flavor */
	uint32_t fw_changelist; /* BuildData::Changelist() */
	uint32_t spare[10];
};

/* Returns the name of @fw_flavor in string. */
char *gcip_fw_flavor_str(enum gcip_fw_flavor fw_flavor);

#endif /* __GCIP_FIRMWARE_H__ */
