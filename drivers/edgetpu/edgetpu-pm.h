/* SPDX-License-Identifier: GPL-2.0 */
/*
 * EdgeTPU power management interface.
 *
 * Copyright (C) 2020 Google, Inc.
 */

#ifndef __EDGETPU_PM_H__
#define __EDGETPU_PM_H__

#include "edgetpu-internal.h"

struct edgetpu_pm_private;
struct edgetpu_pm;

struct edgetpu_pm_handlers {
	/* For initial setup after the interface initialized */
	int (*after_create)(struct edgetpu_pm *etpm);
	/* For clean-up before the interface is destroyed */
	void (*before_destroy)(struct edgetpu_pm *etpm);
	/* Platform-specific power up. Nesting is handled at generic layer */
	int (*power_up)(struct edgetpu_pm *etpm);
	/* Platform-specific power down. Nesting is handled at generic layer */
	int (*power_down)(struct edgetpu_pm *etpm);
};

struct edgetpu_pm {
	struct edgetpu_dev *etdev;
	struct edgetpu_pm_private *p;
};

/*
 * These mimic the pm_runtime_{get|put} functions to keep a reference count
 * of requests in order to keep the device up and turn it off if the platform
 * supports it.
 *
 * Since these functions are used by the edgetpu-fs and edgetpu-firmware
 * layers, (which have their own internal locks) no locking is provided here.
 *
 * Callers are responsible for holding any necessary locks.
 */

/*
 * Tries to acquire the internal lock that ensures power_up_counter won't be
 * modified.
 *
 * Returns 1 if the lock has been acquired successfully, 0 otherwise.
 */
int edgetpu_pm_trylock(struct edgetpu_pm *etpm);
void edgetpu_pm_unlock(struct edgetpu_pm *etpm);

/*
 * Increase power_up_count if it's already powered on.
 *
 * Caller calls edgetpu_pm_put() to decrease power_up_count if this function
 * returned true, otherwise put() shouldn't be called.
 *
 * Return false if device is not powered, true otherwise.
 */
bool edgetpu_pm_get_if_powered(struct edgetpu_pm *etpm);
/*
 * Increase power_up_count for active state, power up the device if previous
 * power_up_count was zero.
 * Returns 0 on success or negative error value
 */
int edgetpu_pm_get(struct edgetpu_pm *etpm);

/* Decrease power_up_count for active state, power off if it reaches zero */
void edgetpu_pm_put(struct edgetpu_pm *etpm);

/* Initialize a power management interface for an edgetpu device */
int edgetpu_pm_create(struct edgetpu_dev *etdev,
		      const struct edgetpu_pm_handlers *handlers);

/* Destroy the power management interface associated with an edgetpu device */
void edgetpu_pm_destroy(struct edgetpu_dev *etdev);

/*
 * When @force is true, ensure device is shut down, regardless of whether there
 * is a client left open.
 *
 * When @force is false, the device is shut down if there is no client open.
 */
void edgetpu_pm_shutdown(struct edgetpu_dev *etdev, bool force);

/* Check if device is powered on. power_up_count is not protected by a lock */
bool edgetpu_is_powered(struct edgetpu_dev *etdev);

#if IS_ENABLED(CONFIG_PM_SLEEP)

int edgetpu_pm_suspend(struct edgetpu_dev *etdev);

int edgetpu_pm_resume(struct edgetpu_dev *etdev);

#endif /* IS_ENABLED(CONFIG_PM_SLEEP) */

#endif /* __EDGETPU_PM_H__ */
