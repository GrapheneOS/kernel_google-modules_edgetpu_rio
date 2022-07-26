/* SPDX-License-Identifier: GPL-2.0-only
 *
 * gs_tmu.h - defines and stubs to build edgetpu driver unit tests
 *
 * Based on gs101_tmu.h
 *  Copyright (C) 2019 Samsung Electronics
 *  Hyeonseong Gil <hs.gill@samsung.com>
 */

#ifndef _GS_TMU_H
#define _GS_TMU_H

enum thermal_pause_state {
	THERMAL_RESUME = 0,
	THERMAL_SUSPEND,
};

typedef int (*tpu_pause_cb)(enum thermal_pause_state action, void *data);

static inline void
register_tpu_thermal_pause_cb(tpu_pause_cb tpu_cb, void *data)
{
}

#endif /* _GS_TMU_H */
