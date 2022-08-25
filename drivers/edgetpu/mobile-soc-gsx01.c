// SPDX-License-Identifier: GPL-2.0
/*
 * Edge TPU functions for GSX01 SoCs.
 *
 * Copyright (C) 2022 Google LLC
 */

#include <linux/acpm_dvfs.h>
#include <linux/device.h>
#include <linux/gsa/gsa_tpu.h>
#include <linux/platform_device.h>
#include <linux/thermal.h>
#include <linux/types.h>
#include <soc/google/bts.h>
#include <soc/google/exynos_pm_qos.h>
#include <soc/google/gs_tmu.h>

#include "edgetpu-internal.h"
#include "edgetpu-firmware.h"
#include "edgetpu-kci.h"
#include "edgetpu-mobile-platform.h"
#include "edgetpu-soc.h"
#include "edgetpu-thermal.h"
#include "mobile-firmware.h"
#include "mobile-soc-gsx01.h"

/* TODO(b/199681752): check whether this domain is still correct for Rio */
#define TPU_ACPM_DOMAIN	7

#define MAX_VOLTAGE_VAL 1250000

#define TPU_DEBUG_REQ (1 << 31)

#define TPU_DEBUG_VALUE_SHIFT (27)
#define TPU_DEBUG_VALUE_MASK ((1 << TPU_DEBUG_VALUE_SHIFT) - 1)
#define TPU_VDD_TPU_DEBUG (0 << TPU_DEBUG_VALUE_SHIFT)
#define TPU_VDD_TPU_M_DEBUG (1 << TPU_DEBUG_VALUE_SHIFT)
#define TPU_VDD_INT_M_DEBUG (2 << TPU_DEBUG_VALUE_SHIFT)
#define TPU_CLK_CORE_DEBUG (3 << TPU_DEBUG_VALUE_SHIFT)
#define TPU_CLK_CTL_DEBUG (4 << TPU_DEBUG_VALUE_SHIFT)
#define TPU_CLK_AXI_DEBUG (5 << TPU_DEBUG_VALUE_SHIFT)
#define TPU_CLK_APB_DEBUG (6 << TPU_DEBUG_VALUE_SHIFT)
#define TPU_CLK_UART_DEBUG (7 << TPU_DEBUG_VALUE_SHIFT)
#define TPU_CORE_PWR_DEBUG (8 << TPU_DEBUG_VALUE_SHIFT)

/*
 * Encode INT/MIF values as a 16 bit pair in the 32-bit return value
 * (in units of MHz, to provide enough range)
 */
#define PM_QOS_INT_SHIFT                (16)
#define PM_QOS_MIF_MASK                 (0xFFFF)
#define PM_QOS_FACTOR                   (1000)

#define SSMT_NS_READ_STREAM_VID_OFFSET(n)     (0x1000u + (0x4u * (n)))
#define SSMT_NS_WRITE_STREAM_VID_OFFSET(n)    (0x1200u + (0x4u * (n)))

#define SSMT_NS_READ_STREAM_VID_REG(base, n)  ((base) + SSMT_NS_READ_STREAM_VID_OFFSET(n))
#define SSMT_NS_WRITE_STREAM_VID_REG(base, n) ((base) + SSMT_NS_WRITE_STREAM_VID_OFFSET(n))

#define SSMT_BYPASS	(1 << 31)

/* TODO(b/240363978): Remove once ACPM is ready. */
#if !IS_ENABLED(CONFIG_EDGETPU_TEST)
unsigned long exynos_acpm_rate = 0;
#endif /* IS_ENABLED(CONFIG_EDGETPU_TEST) */

static int gsx01_parse_ssmt(struct edgetpu_mobile_platform_dev *etmdev)
{
	struct edgetpu_dev *etdev = &etmdev->edgetpu_dev;
	struct platform_device *pdev = to_platform_device(etdev->dev);
	struct resource *res;
	int ret, i;
	void __iomem *ssmt_base;
	char ssmt_name[] = "ssmt_d0";

	etmdev->ssmt_base =
		devm_kcalloc(etdev->dev, etdev->num_ssmts, sizeof(*etmdev->ssmt_base), GFP_KERNEL);

	if (!etmdev->ssmt_base)
		return -ENOMEM;

	for (i = 0; i < etdev->num_ssmts; i++) {
		sprintf(ssmt_name, "ssmt_d%d", i);

		res = platform_get_resource_byname(pdev, IORESOURCE_MEM, ssmt_name);
		if (!res) {
			etdev_warn(etdev, "Failed to find SSMT_D%d register base", i);
			return -EINVAL;
		}
		ssmt_base = devm_ioremap_resource(&pdev->dev, res);
		if (IS_ERR(ssmt_base)) {
			ret = PTR_ERR(ssmt_base);
			etdev_warn(etdev, "Failed to map SSMT_D%d register base: %d", i, ret);
			return ret;
		}
		etmdev->ssmt_base[i] = ssmt_base;
	}

	return 0;
}

void edgetpu_soc_init(struct edgetpu_dev *etdev)
{
	struct edgetpu_mobile_platform_dev *etmdev = to_mobile_dev(etdev);
	int ret;

	ret = gsx01_parse_ssmt(etmdev);
	if (ret)
		dev_warn(etdev->dev, "SSMT setup failed (%d). Context isolation not enforced", ret);
}

static void gsx01_setup_ssmt(struct edgetpu_dev *etdev)
{
	struct edgetpu_mobile_platform_dev *etmdev = to_mobile_dev(etdev);
	int i, j;

	for (i = 0; i < etdev->num_ssmts; i++)
		if (!etmdev->ssmt_base[i])
			return;

	for (i = 0; i < etdev->num_ssmts; i++) {
		etdev_dbg(etdev, "Setting up SSMT_D%d to feed-through mode\n", i);

		for (j = 0; j < EDGETPU_MAX_STREAM_ID; j++) {
			writel(SSMT_BYPASS, SSMT_NS_READ_STREAM_VID_REG(etmdev->ssmt_base[i], j));
			writel(SSMT_BYPASS, SSMT_NS_WRITE_STREAM_VID_REG(etmdev->ssmt_base[i], j));
		}
	}
}

int edgetpu_soc_prepare_firmware(struct edgetpu_dev *etdev)
{
	gsx01_setup_ssmt(etdev);
	return 0;
}

static void gsx01_cleanup_bts_scenario(struct edgetpu_dev *etdev)
{
	struct edgetpu_mobile_platform_dev *etmdev = to_mobile_dev(etdev);
	struct edgetpu_mobile_platform_pwr *platform_pwr = &etmdev->platform_pwr;
	int performance_scenario = platform_pwr->performance_scenario;

	if (!performance_scenario)
		return;

	mutex_lock(&platform_pwr->scenario_lock);
	while (platform_pwr->scenario_count) {
		int ret = bts_del_scenario(performance_scenario);

		if (ret) {
			platform_pwr->scenario_count = 0;
			etdev_warn_once(etdev, "error %d in cleaning up BTS scenario %u\n", ret,
					performance_scenario);
			break;
		}
		platform_pwr->scenario_count--;
	}
	mutex_unlock(&platform_pwr->scenario_lock);
}

static void gsx01_activate_bts_scenario(struct edgetpu_dev *etdev)
{
	struct edgetpu_mobile_platform_dev *etmdev = to_mobile_dev(etdev);
	struct edgetpu_mobile_platform_pwr *platform_pwr = &etmdev->platform_pwr;
	int performance_scenario = platform_pwr->performance_scenario;

	/* bts_add_scenario() keeps track of reference count internally.*/
	int ret;

	if (!performance_scenario)
		return;
	mutex_lock(&platform_pwr->scenario_lock);
	ret = bts_add_scenario(performance_scenario);
	if (ret)
		etdev_warn_once(etdev, "error %d adding BTS scenario %u\n", ret,
				performance_scenario);
	else
		platform_pwr->scenario_count++;

	etdev_dbg(etdev, "BTS Scenario activated: %d\n", platform_pwr->scenario_count);
	mutex_unlock(&platform_pwr->scenario_lock);
}

static void gsx01_deactivate_bts_scenario(struct edgetpu_dev *etdev)
{
	/* bts_del_scenario() keeps track of reference count internally.*/
	int ret;
	struct edgetpu_mobile_platform_dev *etmdev = to_mobile_dev(etdev);
	struct edgetpu_mobile_platform_pwr *platform_pwr = &etmdev->platform_pwr;
	int performance_scenario = platform_pwr->performance_scenario;

	if (!performance_scenario)
		return;
	mutex_lock(&platform_pwr->scenario_lock);
	if (!platform_pwr->scenario_count) {
		etdev_warn(etdev, "Unbalanced bts deactivate\n");
		mutex_unlock(&platform_pwr->scenario_lock);
		return;
	}
	ret = bts_del_scenario(performance_scenario);
	if (ret)
		etdev_warn_once(etdev, "error %d deleting BTS scenario %u\n", ret,
				performance_scenario);
	else
		platform_pwr->scenario_count--;

	etdev_dbg(etdev, "BTS Scenario deactivated: %d\n", platform_pwr->scenario_count);
	mutex_unlock(&platform_pwr->scenario_lock);
}

static void gsx01_set_bts(struct edgetpu_dev *etdev, u16 bts_val)
{
	etdev_dbg(etdev, "%s: bts request - val = %u\n", __func__, bts_val);

	switch (bts_val) {
	case 0:
		gsx01_deactivate_bts_scenario(etdev);
		break;
	case 1:
		gsx01_activate_bts_scenario(etdev);
		break;
	default:
		etdev_warn(etdev, "%s: invalid BTS request value: %u\n", __func__, bts_val);
		break;
	}
}

static void gsx01_set_pm_qos(struct edgetpu_dev *etdev, u32 pm_qos_val)
{
	struct edgetpu_mobile_platform_dev *etmdev = to_mobile_dev(etdev);
	struct edgetpu_mobile_platform_pwr *platform_pwr = &etmdev->platform_pwr;
	s32 int_val = (pm_qos_val >> PM_QOS_INT_SHIFT) * PM_QOS_FACTOR;
	s32 mif_val = (pm_qos_val & PM_QOS_MIF_MASK) * PM_QOS_FACTOR;

	etdev_dbg(etdev, "%s: pm_qos request - int = %d mif = %d\n", __func__, int_val, mif_val);

	exynos_pm_qos_update_request(&platform_pwr->int_min, int_val);
	exynos_pm_qos_update_request(&platform_pwr->mif_min, mif_val);
}

void edgetpu_soc_handle_reverse_kci(struct edgetpu_dev *etdev,
				    struct gcip_kci_response_element *resp)
{
	int ret;

	switch (resp->code) {
	case RKCI_CODE_PM_QOS_BTS:
		/* FW indicates to ignore the request by setting them to undefined values. */
		if (resp->retval != (typeof(resp->retval))~0ull)
			gsx01_set_pm_qos(etdev, resp->retval);
		if (resp->status != (typeof(resp->status))~0ull)
			gsx01_set_bts(etdev, resp->status);
		ret = edgetpu_kci_resp_rkci_ack(etdev, resp);
		if (ret)
			etdev_err(etdev, "failed to send rkci resp for %llu (%d)", resp->seq, ret);
		break;
	default:
		etdev_warn(etdev, "%s: Unrecognized KCI request: %u\n", __func__, resp->code);
		break;
	}
}

long edgetpu_soc_pm_get_rate(int flags)
{
	return exynos_acpm_get_rate(TPU_ACPM_DOMAIN, flags);
}

int edgetpu_soc_pm_set_rate(unsigned long rate)
{
	return exynos_acpm_set_rate(TPU_ACPM_DOMAIN, rate);
}

int edgetpu_soc_pm_set_init_freq(unsigned long freq)
{
	return exynos_acpm_set_init_freq(TPU_ACPM_DOMAIN, freq);
}

int edgetpu_soc_pm_set_policy(u64 val)
{
	return exynos_acpm_set_policy(TPU_ACPM_DOMAIN, val);
}

static int edgetpu_core_rate_get(void *data, u64 *val)
{
	*val = edgetpu_soc_pm_get_rate(TPU_DEBUG_REQ | TPU_CLK_CORE_DEBUG);
	return 0;
}

static int edgetpu_core_rate_set(void *data, u64 val)
{
	unsigned long dbg_rate_req;

	dbg_rate_req = TPU_DEBUG_REQ | TPU_CLK_CORE_DEBUG;
	dbg_rate_req |= val;

	return edgetpu_soc_pm_set_rate(dbg_rate_req);
}

static int edgetpu_ctl_rate_get(void *data, u64 *val)
{
	*val = edgetpu_soc_pm_get_rate(TPU_DEBUG_REQ | TPU_CLK_CTL_DEBUG);
	return 0;
}

static int edgetpu_ctl_rate_set(void *data, u64 val)
{
	unsigned long dbg_rate_req;

	dbg_rate_req = TPU_DEBUG_REQ | TPU_CLK_CTL_DEBUG;
	dbg_rate_req |= 1000;

	return edgetpu_soc_pm_set_rate(dbg_rate_req);
}

static int edgetpu_axi_rate_get(void *data, u64 *val)
{
	*val = edgetpu_soc_pm_get_rate(TPU_DEBUG_REQ | TPU_CLK_AXI_DEBUG);
	return 0;
}

static int edgetpu_axi_rate_set(void *data, u64 val)
{
	unsigned long dbg_rate_req;

	dbg_rate_req = TPU_DEBUG_REQ | TPU_CLK_AXI_DEBUG;
	dbg_rate_req |= 1000;

	return edgetpu_soc_pm_set_rate(dbg_rate_req);
}

static int edgetpu_apb_rate_get(void *data, u64 *val)
{
	*val = edgetpu_soc_pm_get_rate(TPU_DEBUG_REQ | TPU_CLK_APB_DEBUG);
	return 0;
}

static int edgetpu_uart_rate_get(void *data, u64 *val)
{
	*val = edgetpu_soc_pm_get_rate(TPU_DEBUG_REQ | TPU_CLK_UART_DEBUG);
	return 0;
}

static int edgetpu_vdd_int_m_set(void *data, u64 val)
{
	struct device *dev = (struct device *)data;
	unsigned long dbg_rate_req;

	if (val > MAX_VOLTAGE_VAL) {
		dev_err(dev, "Preventing INT_M voltage > %duV", MAX_VOLTAGE_VAL);
		return -EINVAL;
	}

	dbg_rate_req = TPU_DEBUG_REQ | TPU_VDD_INT_M_DEBUG;
	dbg_rate_req |= val;

	return edgetpu_soc_pm_set_rate(dbg_rate_req);
}

static int edgetpu_vdd_int_m_get(void *data, u64 *val)
{
	*val = edgetpu_soc_pm_get_rate(TPU_DEBUG_REQ | TPU_VDD_INT_M_DEBUG);
	return 0;
}

static int edgetpu_vdd_tpu_set(void *data, u64 val)
{
	int ret;
	struct device *dev = (struct device *)data;
	unsigned long dbg_rate_req;

	if (val > MAX_VOLTAGE_VAL) {
		dev_err(dev, "Preventing VDD_TPU voltage > %duV", MAX_VOLTAGE_VAL);
		return -EINVAL;
	}

	dbg_rate_req = TPU_DEBUG_REQ | TPU_VDD_TPU_DEBUG;
	dbg_rate_req |= val;

	ret = edgetpu_soc_pm_set_rate(dbg_rate_req);
	return ret;
}

static int edgetpu_vdd_tpu_get(void *data, u64 *val)
{
	*val = edgetpu_soc_pm_get_rate(TPU_DEBUG_REQ | TPU_VDD_TPU_DEBUG);
	return 0;
}

static int edgetpu_vdd_tpu_m_set(void *data, u64 val)
{
	int ret;
	struct device *dev = (struct device *)data;
	unsigned long dbg_rate_req;

	if (val > MAX_VOLTAGE_VAL) {
		dev_err(dev, "Preventing VDD_TPU voltage > %duV", MAX_VOLTAGE_VAL);
		return -EINVAL;
	}

	dbg_rate_req = TPU_DEBUG_REQ | TPU_VDD_TPU_M_DEBUG;
	dbg_rate_req |= val;

	ret = edgetpu_soc_pm_set_rate(dbg_rate_req);
	return ret;
}

static int edgetpu_vdd_tpu_m_get(void *data, u64 *val)
{
	*val = edgetpu_soc_pm_get_rate(TPU_DEBUG_REQ | TPU_VDD_TPU_M_DEBUG);
	return 0;
}

DEFINE_DEBUGFS_ATTRIBUTE(fops_tpu_core_rate, edgetpu_core_rate_get, edgetpu_core_rate_set,
			 "%llu\n");
DEFINE_DEBUGFS_ATTRIBUTE(fops_tpu_ctl_rate, edgetpu_ctl_rate_get, edgetpu_ctl_rate_set, "%llu\n");
DEFINE_DEBUGFS_ATTRIBUTE(fops_tpu_axi_rate, edgetpu_axi_rate_get, edgetpu_axi_rate_set, "%llu\n");
DEFINE_DEBUGFS_ATTRIBUTE(fops_tpu_apb_rate, edgetpu_apb_rate_get, NULL, "%llu\n");
DEFINE_DEBUGFS_ATTRIBUTE(fops_tpu_uart_rate, edgetpu_uart_rate_get, NULL, "%llu\n");
DEFINE_DEBUGFS_ATTRIBUTE(fops_tpu_vdd_int_m, edgetpu_vdd_int_m_get, edgetpu_vdd_int_m_set,
			 "%llu\n");
DEFINE_DEBUGFS_ATTRIBUTE(fops_tpu_vdd_tpu, edgetpu_vdd_tpu_get, edgetpu_vdd_tpu_set, "%llu\n");
DEFINE_DEBUGFS_ATTRIBUTE(fops_tpu_vdd_tpu_m, edgetpu_vdd_tpu_m_get, edgetpu_vdd_tpu_m_set,
			 "%llu\n");

void edgetpu_soc_pm_power_down(struct edgetpu_dev *etdev)
{
	struct edgetpu_mobile_platform_dev *etmdev = to_mobile_dev(etdev);
	struct edgetpu_mobile_platform_pwr *platform_pwr = &etmdev->platform_pwr;

	/* Remove our vote for INT/MIF state (if any) */
	exynos_pm_qos_update_request(&platform_pwr->int_min, 0);
	exynos_pm_qos_update_request(&platform_pwr->mif_min, 0);

	gsx01_cleanup_bts_scenario(etdev);
}

int edgetpu_soc_pm_init(struct edgetpu_dev *etdev)
{
	struct device *dev = etdev->dev;
	struct edgetpu_mobile_platform_dev *etmdev = to_mobile_dev(etdev);
	struct edgetpu_mobile_platform_pwr *platform_pwr = &etmdev->platform_pwr;

	exynos_pm_qos_add_request(&platform_pwr->int_min, PM_QOS_DEVICE_THROUGHPUT, 0);
	exynos_pm_qos_add_request(&platform_pwr->mif_min, PM_QOS_BUS_THROUGHPUT, 0);

	platform_pwr->performance_scenario = bts_get_scenindex("tpu_performance");
	if (!platform_pwr->performance_scenario)
		dev_warn(etdev->dev, "tpu_performance BTS scenario not found\n");
	platform_pwr->scenario_count = 0;

	debugfs_create_file("vdd_tpu", 0660, platform_pwr->debugfs_dir, dev, &fops_tpu_vdd_tpu);
	debugfs_create_file("vdd_tpu_m", 0660, platform_pwr->debugfs_dir, dev, &fops_tpu_vdd_tpu_m);
	debugfs_create_file("vdd_int_m", 0660, platform_pwr->debugfs_dir, dev, &fops_tpu_vdd_int_m);
	debugfs_create_file("core_rate", 0660, platform_pwr->debugfs_dir, dev, &fops_tpu_core_rate);
	debugfs_create_file("ctl_rate", 0660, platform_pwr->debugfs_dir, dev, &fops_tpu_ctl_rate);
	debugfs_create_file("axi_rate", 0660, platform_pwr->debugfs_dir, dev, &fops_tpu_axi_rate);
	debugfs_create_file("apb_rate", 0440, platform_pwr->debugfs_dir, dev, &fops_tpu_apb_rate);
	debugfs_create_file("uart_rate", 0440, platform_pwr->debugfs_dir, dev, &fops_tpu_uart_rate);
	return 0;
}

void edgetpu_soc_pm_exit(struct edgetpu_dev *etdev)
{
	struct edgetpu_mobile_platform_dev *etmdev = to_mobile_dev(etdev);
	struct edgetpu_mobile_platform_pwr *platform_pwr = &etmdev->platform_pwr;

	gsx01_cleanup_bts_scenario(etdev);
	exynos_pm_qos_remove_request(&platform_pwr->int_min);
	exynos_pm_qos_remove_request(&platform_pwr->mif_min);
}

static int tpu_pause_callback(enum thermal_pause_state action, void *dev)
{
	int ret = -EINVAL;

	if (!dev)
		return ret;

	if (action == THERMAL_SUSPEND)
		ret = edgetpu_thermal_suspend(dev);
	else if (action == THERMAL_RESUME)
		ret = edgetpu_thermal_resume(dev);

	return ret;
}

void edgetpu_soc_thermal_init(struct edgetpu_thermal *thermal)
{
	register_tpu_thermal_pause_cb(tpu_pause_callback, thermal->dev);
}
