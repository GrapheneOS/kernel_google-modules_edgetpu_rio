/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Common authenticated image format for Google SoCs
 *
 * Copyright (C) 2022 Google LLC
 */

#ifndef __GCIP_COMMON_IMAGE_HEADER_H__
#define __GCIP_COMMON_IMAGE_HEADER_H__

#include "gcip-image-config.h"

#define GCIP_FW_HEADER_SIZE (0x1000)

struct gcip_common_image_sub_header_common {
	int magic;
	int generation;
	int rollback_info;
	int length;
	char flags[16];
};

struct gcip_common_image_sub_header_gen1 {
	char body_hash[32];
	char chip_id[32];
	char auth_config[256];
	struct gcip_image_config image_config;
};

struct gcip_common_image_sub_header_gen2 {
	char body_hash[64];
	char chip_id[32];
	char auth_config[256];
	struct gcip_image_config image_config;
};

struct gcip_common_image_header {
	char sig[512];
	char pub[512];
	struct {
		struct gcip_common_image_sub_header_common common;
		union {
			struct gcip_common_image_sub_header_gen1 gen1;
			struct gcip_common_image_sub_header_gen2 gen2;
		};
	};
};

/*
 * Returns the image config field from a common image header
 * or NULL if the header has an invalid generation identifier
 */
static inline struct gcip_image_config *
get_image_config_from_hdr(struct gcip_common_image_header *hdr)
{
	switch (hdr->common.generation) {
	case 1:
		return &hdr->gen1.image_config;
	case 2:
		return &hdr->gen2.image_config;
	}
	return NULL;
}

#endif  /* __GCIP_COMMON_IMAGE_HEADER_H__ */
