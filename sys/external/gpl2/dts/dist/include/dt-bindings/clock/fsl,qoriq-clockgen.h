/*	$NetBSD: fsl,qoriq-clockgen.h,v 1.1.1.1 2021/11/07 16:49:59 jmcneill Exp $	*/

/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef DT_CLOCK_FSL_QORIQ_CLOCKGEN_H
#define DT_CLOCK_FSL_QORIQ_CLOCKGEN_H

#define QORIQ_CLK_SYSCLK	0
#define QORIQ_CLK_CMUX		1
#define QORIQ_CLK_HWACCEL	2
#define QORIQ_CLK_FMAN		3
#define QORIQ_CLK_PLATFORM_PLL	4
#define QORIQ_CLK_CORECLK	5

#define QORIQ_CLK_PLL_DIV(x)	((x) - 1)

#endif /* DT_CLOCK_FSL_QORIQ_CLOCKGEN_H */
