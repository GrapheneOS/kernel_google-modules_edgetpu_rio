/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Fallback header for systems without Exynos ACPM support.
 * TODO(b/240363978): Remove once ACPM is ready.
 *
 * Copyright (C) 2021 Google, Inc.
 */

#ifndef __ACPM_DVFS_H__
#define __ACPM_DVFS_H__

static inline int exynos_acpm_set_init_freq(unsigned int dfs_id, unsigned long freq)
{
	return 0;
}

static inline int exynos_acpm_set_policy(unsigned int id, unsigned long policy)
{
	return 0;
}

#if IS_ENABLED(CONFIG_EDGETPU_TEST)

int exynos_acpm_set_rate(unsigned int id, unsigned long rate);
unsigned long exynos_acpm_get_rate(unsigned int id, unsigned long dbg_val);

#else /* IS_ENABLED(CONFIG_EDGETPU_TEST) */

extern unsigned long exynos_acpm_rate;

static inline int exynos_acpm_set_rate(unsigned int id, unsigned long rate)
{
	exynos_acpm_rate = rate;
	return 0;
}

static inline unsigned long exynos_acpm_get_rate(unsigned int id,
						 unsigned long dbg_val)
{
	return exynos_acpm_rate;
}

#endif /* IS_ENABLED(CONFIG_EDGETPU_TEST) */

#endif /* __ACPM_DVFS_H__ */
