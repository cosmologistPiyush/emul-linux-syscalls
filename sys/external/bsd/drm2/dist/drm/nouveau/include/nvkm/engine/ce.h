/*	$NetBSD: ce.h,v 1.3 2021/12/18 23:45:33 riastradh Exp $	*/

/* SPDX-License-Identifier: MIT */
#ifndef __NVKM_CE_H__
#define __NVKM_CE_H__
#include <engine/falcon.h>

int gt215_ce_new(struct nvkm_device *, int, struct nvkm_engine **);
int gf100_ce_new(struct nvkm_device *, int, struct nvkm_engine **);
int gk104_ce_new(struct nvkm_device *, int, struct nvkm_engine **);
int gm107_ce_new(struct nvkm_device *, int, struct nvkm_engine **);
int gm200_ce_new(struct nvkm_device *, int, struct nvkm_engine **);
int gp100_ce_new(struct nvkm_device *, int, struct nvkm_engine **);
int gp102_ce_new(struct nvkm_device *, int, struct nvkm_engine **);
int gv100_ce_new(struct nvkm_device *, int, struct nvkm_engine **);
int tu102_ce_new(struct nvkm_device *, int, struct nvkm_engine **);
#endif
