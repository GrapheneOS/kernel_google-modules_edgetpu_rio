/* SPDX-License-Identifier: GPL-2.0 */
/*
 * EdgeTPU power management interface.
 *
 * Copyright (C) 2020 Google, Inc.
 */

#ifndef __EDGETPU_PM_H__
#define __EDGETPU_PM_H__

#include <linux/pm.h>

#include <gcip/gcip-pm.h>

#include "edgetpu-config.h"
#include "edgetpu-internal.h"

/* Power management data for an EdgeTPU device. */
struct edgetpu_pm {
	/* Pointer to GCIP layer PM data. */
	struct gcip_pm *gpm;
	struct dentry *debugfs_dir;
	struct mutex policy_lock;
	enum edgetpu_pwr_state curr_policy;
	struct mutex state_lock;
	u64 requested_state;
	/*
	 * Min/Max frequencies, in kHz, requested via debugfs.
	 * Protected by `freq_limits_lock`.
	 */
	struct mutex freq_limits_lock;
	u32 min_freq;
	u32 max_freq;
};

extern const struct dev_pm_ops edgetpu_pm_ops;

/* Return a pointer to the struct gcip_pm for the device. */

static inline struct gcip_pm *edgetpu_gcip_pm(struct edgetpu_dev *etdev)
{
	return etdev->pm->gpm;
}

/*
 * Increases power up count if the device is already powered on.
 * Wrapper for gcip_pm_get_if_powered.
 */
static inline int edgetpu_pm_get_if_powered(struct edgetpu_dev *etdev, bool blocking)
{
	return gcip_pm_get_if_powered(etdev->pm->gpm, blocking);
}

/*
 * Increases power up count and powers up the device if currently off.
 * Wrapper for gcip_pm_get.
 */
static inline int edgetpu_pm_get(struct edgetpu_dev *etdev)
{
	return gcip_pm_get(etdev->pm->gpm);
}

/*
 * Decreases @pm->count and powers off the device if @pm->count reaches zero.
 * Wrapper for gcip_pm_put.
 */
static inline void edgetpu_pm_put(struct edgetpu_dev *etdev)
{
	gcip_pm_put(etdev->pm->gpm);
}

/* Gets the power up counter. Note that this is checked without PM lock. */
static inline int edgetpu_pm_get_count(struct edgetpu_dev *etdev)
{
	return gcip_pm_get_count(etdev->pm->gpm);
}

/* Checks if device is already on. Note that this is checked without PM lock. */
static inline bool edgetpu_pm_is_powered(struct edgetpu_dev *etdev)
{
	return gcip_pm_is_powered(etdev->pm->gpm);
}

/* Shuts down the device if @pm->count equals to 0 or @force is true. */
static inline void edgetpu_pm_shutdown(struct edgetpu_dev *etdev, bool force)
{
	gcip_pm_shutdown(etdev->pm->gpm, force);
}


/* Lock the PM lock. Wrapper for gcip_pm_lock. */
static inline void edgetpu_pm_lock(struct edgetpu_dev *etdev)
{
	gcip_pm_lock(etdev->pm->gpm);
}

/*
 * Try to lock the PM lock.  Wrapper for gcip_pm_trylock.
 * Returns 1 if the lock has been acquired successfully, and 0 on contention.
 */
static inline int edgetpu_pm_trylock(struct edgetpu_dev *etdev)
{
	return gcip_pm_trylock(etdev->pm->gpm);
}

/* Unlock the PM lock. Wrapper for gcip_pm_unlock*/
static inline void edgetpu_pm_unlock(struct edgetpu_dev *etdev)
{
	gcip_pm_unlock(etdev->pm->gpm);
}

/* Initialize a power management interface for an edgetpu device */
int edgetpu_pm_create(struct edgetpu_dev *etdev);

/* Destroy the power management interface associated with an edgetpu device */
void edgetpu_pm_destroy(struct edgetpu_dev *etdev);

#endif /* __EDGETPU_PM_H__ */
