/*	$NetBSD: mspdec.h,v 1.3 2021/12/18 23:45:33 riastradh Exp $	*/

/* SPDX-License-Identifier: MIT */
#ifndef __NVKM_MSPDEC_H__
#define __NVKM_MSPDEC_H__
#include <engine/falcon.h>
int g98_mspdec_new(struct nvkm_device *, int, struct nvkm_engine **);
int gt215_mspdec_new(struct nvkm_device *, int, struct nvkm_engine **);
int gf100_mspdec_new(struct nvkm_device *, int, struct nvkm_engine **);
int gk104_mspdec_new(struct nvkm_device *, int, struct nvkm_engine **);
#endif
