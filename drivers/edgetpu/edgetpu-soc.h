/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Edge TPU driver SoC-specific APIs.
 *
 * Copyright (C) 2022 Google LLC
 */

#ifndef __EDGETPU_SOC_H__
#define __EDGETPU_SOC_H__

#include <linux/types.h>

#include "edgetpu-internal.h"
#include "edgetpu-thermal.h"

/* SoC-specific calls for the following functions. */

/* Prep for running firmware: set access control, etc. */
int edgetpu_soc_prepare_firmware(struct edgetpu_dev *etdev);

/* Power management get TPU clock rate */
long edgetpu_soc_pm_get_rate(int flags);

/* Power management set TPU clock rate */
int edgetpu_soc_pm_set_rate(unsigned long rate);

/* Set initial TPU freq */
int edgetpu_soc_pm_set_init_freq(unsigned long freq);

/* Set PM policy */
int edgetpu_soc_pm_set_policy(u64 val);

/* Init thermal subsystem SoC specifics for TPU */
void edgetpu_soc_thermal_init(struct edgetpu_thermal *thermal);

#endif /* __EDGETPU_SOC_H__ */
