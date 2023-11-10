# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for GCIP framework.
#

CONFIG_GCIP		?= m
obj-$(CONFIG_GCIP)	+= gcip.o iif/

gcip-objs		:= gcip-alloc-helper.o \
			   gcip-dma-fence.o \
			   gcip-domain-pool.o \
			   gcip-fault-injection.o \
			   gcip-firmware.o \
			   gcip-image-config.o \
			   gcip-iommu.o \
			   gcip-kci.o \
			   gcip-mailbox.o \
			   gcip-mem-pool.o \
			   gcip-pm.o \
			   gcip-resource-accessor.o \
			   gcip-slc.o \
			   gcip-telemetry.o \
			   gcip-thermal.o \
			   gcip-usage-stats.o

CURRENT_DIR=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))

ccflags-y += -I$(CURRENT_DIR)/../../include


modules modules_install clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(M) W=1 $(KBUILD_OPTIONS) $(@)
