/*	$NetBSD: acpi.h,v 1.3 2021/12/18 23:45:34 riastradh Exp $	*/

/* SPDX-License-Identifier: MIT */
#ifndef __NVKM_DEVICE_ACPI_H__
#define __NVKM_DEVICE_ACPI_H__
#include <core/os.h>
struct nvkm_device;

void nvkm_acpi_init(struct nvkm_device *);
void nvkm_acpi_fini(struct nvkm_device *);
#endif
