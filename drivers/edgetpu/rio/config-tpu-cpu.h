/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Chip-dependent configuration for TPU CPU.
 *
 * Copyright (C) 2021 Google, Inc.
 */

#ifndef __RIO_CONFIG_TPU_CPU_H__
#define __RIO_CONFIG_TPU_CPU_H__

#define EDGETPU_REG_RESET_CONTROL                       0x190018
#define EDGETPU_REG_INSTRUCTION_REMAP_CONTROL           0x190070
#define EDGETPU_REG_INSTRUCTION_REMAP_BASE              0x190080
#define EDGETPU_REG_INSTRUCTION_REMAP_LIMIT             0x190090
#define EDGETPU_REG_INSTRUCTION_REMAP_NEW_BASE          0x1900a0
#define EDGETPU_REG_INSTRUCTION_REMAP_SECURITY          0x1900b0
#define EDGETPU_REG_SECURITY                            0x190060
#define EDGETPU_REG_POWER_CONTROL                       0x1A0010
#define EDGETPU_REG_LPM_CONTROL                         0x1D0020
#define PSTATE_SHIFT					1
#define PSTATE						(1 << PSTATE_SHIFT)
#define PREQ						(1 << 2)
#define PDENY						(1 << 3)
#define PACCEPT						(1 << 4)
#define PACTIVE						(1 << 6)

#endif /* __RIO_CONFIG_TPU_CPU_H__ */
