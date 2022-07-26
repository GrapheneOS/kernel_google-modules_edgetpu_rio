/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Edge TPU driver SoC-specific APIs.
 *
 * Copyright (C) 2022 Google LLC
 */

#ifndef __EDGETPU_SOC_H__
#define __EDGETPU_SOC_H__

/* SoC-specific prep for running firmware: set access control, etc. */
int edgetpu_soc_prepare_firmware(struct edgetpu_dev *etdev);

#endif /* __EDGETPU_SOC_H__ */
