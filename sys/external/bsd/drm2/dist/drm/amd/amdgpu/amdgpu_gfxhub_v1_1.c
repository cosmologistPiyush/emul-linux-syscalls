/*	$NetBSD: amdgpu_gfxhub_v1_1.c,v 1.2 2021/12/18 23:44:58 riastradh Exp $	*/

/*
 * Copyright 2018 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 */
#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: amdgpu_gfxhub_v1_1.c,v 1.2 2021/12/18 23:44:58 riastradh Exp $");

#include "amdgpu.h"
#include "gfxhub_v1_1.h"

#include "gc/gc_9_2_1_offset.h"
#include "gc/gc_9_2_1_sh_mask.h"

#include "soc15_common.h"

int gfxhub_v1_1_get_xgmi_info(struct amdgpu_device *adev)
{
	u32 xgmi_lfb_cntl = RREG32_SOC15(GC, 0, mmMC_VM_XGMI_LFB_CNTL);
	u32 max_region =
		REG_GET_FIELD(xgmi_lfb_cntl, MC_VM_XGMI_LFB_CNTL, PF_MAX_REGION);
	u32 max_num_physical_nodes   = 0;
	u32 max_physical_node_id     = 0;

	switch (adev->asic_type) {
	case CHIP_VEGA20:
		max_num_physical_nodes   = 4;
		max_physical_node_id     = 3;
		break;
	case CHIP_ARCTURUS:
		max_num_physical_nodes   = 8;
		max_physical_node_id     = 7;
		break;
	default:
		return -EINVAL;
	}

	/* PF_MAX_REGION=0 means xgmi is disabled */
	if (max_region) {
		adev->gmc.xgmi.num_physical_nodes = max_region + 1;
		if (adev->gmc.xgmi.num_physical_nodes > max_num_physical_nodes)
			return -EINVAL;

		adev->gmc.xgmi.physical_node_id =
			REG_GET_FIELD(xgmi_lfb_cntl, MC_VM_XGMI_LFB_CNTL, PF_LFB_REGION);
		if (adev->gmc.xgmi.physical_node_id > max_physical_node_id)
			return -EINVAL;
		adev->gmc.xgmi.node_segment_size = REG_GET_FIELD(
			RREG32_SOC15(GC, 0, mmMC_VM_XGMI_LFB_SIZE),
			MC_VM_XGMI_LFB_SIZE, PF_LFB_SIZE) << 24;
	}

	return 0;
}
