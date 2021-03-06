/*	$NetBSD: priv.h,v 1.3 2021/12/18 23:45:40 riastradh Exp $	*/

/* SPDX-License-Identifier: MIT */
#ifndef __NVKM_IBUS_PRIV_H__
#define __NVKM_IBUS_PRIV_H__

#include <subdev/ibus.h>

void gf100_ibus_intr(struct nvkm_subdev *);
void gk104_ibus_intr(struct nvkm_subdev *);
#endif
