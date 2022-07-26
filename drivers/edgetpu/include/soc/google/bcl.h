/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __BCL_H__
#define __BCL_H__

struct gs101_bcl_dev;

static inline unsigned int gs101_get_mpmm(struct gs101_bcl_dev *data)
{
	return 0;
}
static inline unsigned int gs101_get_ppm(struct gs101_bcl_dev *data)
{
	return 0;
}
static inline int gs101_set_ppm(struct gs101_bcl_dev *data, unsigned int value)
{
	return 0;
}
static inline int gs101_set_mpmm(struct gs101_bcl_dev *data, unsigned int value)
{
	return 0;
}
static inline struct gs101_bcl_dev *gs101_retrieve_bcl_handle(void)
{
	return NULL;
}
static inline int gs101_init_gpu_ratio(struct gs101_bcl_dev *data)
{
	return 0;
}
static inline int gs101_init_tpu_ratio(struct gs101_bcl_dev *data)
{
	return 0;
}

#endif /* __BCL_H__ */
