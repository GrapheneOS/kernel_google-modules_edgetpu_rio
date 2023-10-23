/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Defines overall definitions for IIF driver.
 *
 * Copyright (C) 2023 Google LLC
 */

#ifndef __IIF_IIF_H__
#define __IIF_IIF_H__

/*
 * The max number of fences can be created per IP.
 * Increasing this value needs to increase the size of fence table.
 */
#define IIF_NUM_FENCES_PER_IP 1024

/*
 * Type of IPs.
 *
 * The order of IP must be matched with the firmware side because the fence ID will be assigned
 * according to the IP type.
 */
enum iif_ip_type {
	IIF_IP_DSP,
	IIF_IP_TPU,
	IIF_IP_GPU,
	IIF_IP_NUM,

	/* Reserve the number of IP type to expand the fence table easily in the future. */
	IIF_IP_RESERVED = 16,
};

#endif /* __IIF_IIF_H__ */
