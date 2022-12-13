# SPDX-License-Identifier: GPL-2.0
#
# Makefile for EdgeTPU framework and dependent drivers.
#

obj-$(CONFIG_RIO)		+= rio.o

KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build
M ?= $(shell pwd)

GIT_PATH=$(KERNEL_SRC)/../private/google-modules/edgetpu/rio
ifeq ($(shell git --git-dir=$(GIT_PATH)/.git rev-parse --is-inside-work-tree),true)
	GIT_REPO_STATE=$(shell (git --git-dir=$(GIT_PATH)/.git --work-tree=$(GIT_PATH) status --porcelain | grep -q .) && echo -dirty)
	ccflags-y       += -DGIT_REPO_TAG=\"$(shell git --git-dir=$(GIT_PATH)/.git rev-parse --short HEAD)$(GIT_REPO_STATE)\"
else
	ccflags-y       += -DGIT_REPO_TAG=\"Not\ a\ git\ repository\"
endif

edgetpu-objs	:= edgetpu-async.o edgetpu-dmabuf.o edgetpu-iremap-pool.o \
		   edgetpu-kci.o edgetpu-mailbox.o edgetpu-mapping.o \
		   edgetpu-sw-watchdog.o edgetpu-telemetry.o \
		   edgetpu-firmware-util.o edgetpu-firmware.o

rio-objs	:= rio-core.o rio-debug-dump.o rio-device-group.o rio-device.o \
		   rio-firmware.o rio-fs.o rio-iommu.o rio-platform.o rio-pm.o \
		   rio-thermal.o rio-usage-stats.o rio-wakelock.o rio-external.o \
		   rio-soc.o $(edgetpu-objs)


ccflags-y	+= -I$(KERNEL_SRC)/../private/google-modules/edgetpu/rio/drivers/edgetpu/include
KBUILD_OPTIONS	+= CONFIG_RIO=m
include $(KERNEL_SRC)/../private/google-modules/soc/gs/Makefile.include

GCIP_DIR=gcip-kernel-driver/drivers/gcip

KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build
M ?= $(shell pwd)

modules modules_install:
	$(MAKE) -C $(KERNEL_SRC) M=$(M)/$(GCIP_DIR) W=1 gcip.o
	$(MAKE) -C $(KERNEL_SRC) M=$(M) W=1 $(KBUILD_OPTIONS) \
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" KBUILD_EXTRA_SYMBOLS="$(EXTRA_SYMBOLS)" $(@)
clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(M)/$(GCIP_DIR) W=1 \
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" KBUILD_EXTRA_SYMBOLS="$(EXTRA_SYMBOLS)" $(@)
	$(MAKE) -C $(KERNEL_SRC) M=$(M) W=1 $(KBUILD_OPTIONS) \
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" KBUILD_EXTRA_SYMBOLS="$(EXTRA_SYMBOLS)" $(@)
