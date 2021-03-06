/*	$NetBSD: nouveau_nvkm_subdev_pmu_gk208.c,v 1.3 2021/12/18 23:45:41 riastradh Exp $	*/

/*
 * Copyright 2013 Red Hat Inc.
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
 * Authors: Ben Skeggs
 */
#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: nouveau_nvkm_subdev_pmu_gk208.c,v 1.3 2021/12/18 23:45:41 riastradh Exp $");

#include "priv.h"
#include "fuc/gk208.fuc5.h"

static const struct nvkm_pmu_func
gk208_pmu = {
	.flcn = &gt215_pmu_flcn,
	.code.data = gk208_pmu_code,
	.code.size = sizeof(gk208_pmu_code),
	.data.data = gk208_pmu_data,
	.data.size = sizeof(gk208_pmu_data),
	.enabled = gf100_pmu_enabled,
	.reset = gf100_pmu_reset,
	.init = gt215_pmu_init,
	.fini = gt215_pmu_fini,
	.intr = gt215_pmu_intr,
	.send = gt215_pmu_send,
	.recv = gt215_pmu_recv,
	.pgob = gk110_pmu_pgob,
};

static const struct nvkm_pmu_fwif
gk208_pmu_fwif[] = {
	{ -1, gf100_pmu_nofw, &gk208_pmu },
	{}
};

int
gk208_pmu_new(struct nvkm_device *device, int index, struct nvkm_pmu **ppmu)
{
	return nvkm_pmu_new_(gk208_pmu_fwif, device, index, ppmu);
}
