/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Definitions for GSx01 SoCs.
 *
 * Copyright (C) 2022 Google LLC
 */

#ifndef __MOBILE_SOC_GSX01_H__
#define __MOBILE_SOC_GSX01_H__

/*
 * Request codes from firmware
 * Values must match with firmware code base
 */
enum gsx01_reverse_kci_code {
	RKCI_CODE_PM_QOS = GCIP_RKCI_CHIP_CODE_FIRST + 1,
	RKCI_CODE_BTS = GCIP_RKCI_CHIP_CODE_FIRST + 2,
	/* The above codes have been deprecated. */

	RKCI_CODE_PM_QOS_BTS = GCIP_RKCI_CHIP_CODE_FIRST + 3,
};

#endif /* __MOBILE_SOC_GSX01_H__ */
