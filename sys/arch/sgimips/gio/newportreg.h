
/*	$NetBSD: newportreg.h,v 1.2 2004/02/07 04:34:34 sekiya Exp $	*/

/*
 * Copyright (c) 2003 Ilpo Ruotsalainen
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * <<Id: LICENSE_GC,v 1.1 2001/10/01 23:24:05 cgd Exp>>
 */

#ifndef _ARCH_SGIMIPS_GIO_NEWPORTREG_H_
#define _ARCH_SGIMIPS_GIO_NEWPORTREG_H_

/* REX3 */

#define NEWPORT_REX3_OFFSET		0xf0000

#define REX3_REG_DRAWMODE1		0x0000
#define  REX3_DRAWMODE1_PLANES_MASK	0x00000007
#define   REX3_DRAWMODE1_PLANES_NONE	0x00000000
#define   REX3_DRAWMODE1_PLANES_RGB	0x00000001
#define   REX3_DRAWMODE1_PLANES_CI	0x00000001
#define   REX3_DRAWMODE1_PLANES_RGBA	0x00000002
#define   REX3_DRAWMODE1_PLANES_OLAY	0x00000004
#define   REX3_DRAWMODE1_PLANES_PUP	0x00000005
#define   REX3_DRAWMODE1_PLANES_CID	0x00000006
#define  REX3_DRAWMODE1_DD_MASK		0x00000018
#define   REX3_DRAWMODE1_DD_DD4		0x00000000
#define   REX3_DRAWMODE1_DD_DD8		0x00000008
#define   REX3_DRAWMODE1_DD_DD12	0x00000010
#define   REX3_DRAWMODE1_DD_DD24	0x00000018
#define  REX3_DRAWMODE1_DBLSRC		0x00000020
#define  REX3_DRAWMODE1_YFLIP		0x00000040
#define  REX3_DRAWMODE1_RWPACKED	0x00000080
#define  REX3_DRAWMODE1_HD_MASK		0x00000300
#define   REX3_DRAWMODE1_HD_HD4		0x00000000
#define   REX3_DRAWMODE1_HD_HD8		0x00000100
#define   REX3_DRAWMODE1_HD_HD12	0x00000200
#define   REX3_DRAWMODE1_HD_HD24	0x00000300
#define  REX3_DRAWMODE1_RWDOUBLE	0x00000400
#define  REX3_DRAWMODE1_SWAPENDIAN	0x00000800
#define  REX3_DRAWMODE1_COMPARE_MASK	0x00007000
#define   REX3_DRAWMODE1_COMPARE_LT	0x00001000
#define   REX3_DRAWMODE1_COMPARE_EQ	0x00002000
#define   REX3_DRAWMODE1_COMPARE_GT	0x00004000
#define  REX3_DRAWMODE1_RGBMODE		0x00008000
#define  REX3_DRAWMODE1_DITHER		0x00010000
#define  REX3_DRAWMODE1_FASTCLEAR	0x00020000
#define  REX3_DRAWMODE1_BLEND		0x00040000
#define  REX3_DRAWMODE1_SFACTOR_MASK	0x00380000
#define   REX3_DRAWMODE1_SFACTOR_ZERO	0x00000000
#define   REX3_DRAWMODE1_SFACTOR_ONE	0x00080000
#define   REX3_DRAWMODE1_SFACTOR_DC	0x00100000
#define   REX3_DRAWMODE1_SFACTOR_MDC	0x00180000
#define   REX3_DRAWMODE1_SFACTOR_SA	0x00200000
#define   REX3_DRAWMODE1_SFACTOR_MSA	0x00280000
#define  REX3_DRAWMODE1_DFACTOR_MASK	0x01c00000
#define   REX3_DRAWMODE1_DFACTOR_ZERO	0x00000000
#define   REX3_DRAWMODE1_DFACTOR_ONE	0x00400000
#define   REX3_DRAWMODE1_DFACTOR_SC	0x00800000
#define   REX3_DRAWMODE1_DFACTOR_MSC	0x00c00000
#define   REX3_DRAWMODE1_DFACTOR_SA	0x01000000
#define   REX3_DRAWMODE1_DFACTOR_MSA	0x01400000
#define  REX3_DRAWMODE1_BACKBLEND	0x02000000
#define  REX3_DRAWMODE1_PREFETCH	0x04000000
#define  REX3_DRAWMODE1_BLENDALPHA	0x08000000
#define  REX3_DRAWMODE1_LOGICOP_MASK	0xf0000000
#define   REX3_DRAWMODE1_LO_ZERO	0x00000000
#define   REX3_DRAWMODE1_LO_AND		0x10000000
#define   REX3_DRAWMODE1_LO_ANDR	0x20000000
#define   REX3_DRAWMODE1_LO_SRC		0x30000000
#define   REX3_DRAWMODE1_LO_ANDI	0x40000000
#define   REX3_DRAWMODE1_LO_DST		0x50000000
#define   REX3_DRAWMODE1_LO_XOR		0x60000000
#define   REX3_DRAWMODE1_LO_OR		0x70000000
#define   REX3_DRAWMODE1_LO_NOR		0x80000000
#define   REX3_DRAWMODE1_LO_XNOR	0x90000000
#define   REX3_DRAWMODE1_LO_NDST	0xa0000000
#define   REX3_DRAWMODE1_LO_ORR		0xb0000000
#define   REX3_DRAWMODE1_LO_NSRC	0xc0000000
#define   REX3_DRAWMODE1_LO_ORI		0xd0000000
#define   REX3_DRAWMODE1_LO_NAND	0xe0000000
#define   REX3_DRAWMODE1_LO_ONE		0xf0000000

#define REX3_REG_DRAWMODE0		0x0004
#define  REX3_DRAWMODE0_OPCODE_MASK	0x00000003
#define   REX3_DRAWMODE0_OPCODE_NOOP	0x00000000
#define   REX3_DRAWMODE0_OPCODE_READ	0x00000001
#define   REX3_DRAWMODE0_OPCODE_DRAW	0x00000002
#define   REX3_DRAWMODE0_OPCODE_SCR2SCR	0x00000003
#define  REX3_DRAWMODE0_ADRMODE_MASK	0x0000001c
#define   REX3_DRAWMODE0_ADRMODE_SPAN	0x00000000
#define   REX3_DRAWMODE0_ADRMODE_BLOCK	0x00000004
#define   REX3_DRAWMODE0_ADRMODE_I_LINE	0x00000008
#define   REX3_DRAWMODE0_ADRMODE_F_LINE	0x0000000c
#define   REX3_DRAWMODE0_ADRMODE_A_LINE	0x00000010
#define  REX3_DRAWMODE0_DOSETUP		0x00000020
#define  REX3_DRAWMODE0_COLORHOST	0x00000040
#define  REX3_DRAWMODE0_ALPHAHOST	0x00000080
#define  REX3_DRAWMODE0_STOPONX		0x00000100
#define  REX3_DRAWMODE0_STOPONY		0x00000200
#define  REX3_DRAWMODE0_SKIPFIRST	0x00000400
#define  REX3_DRAWMODE0_SKIPLAST	0x00000800
#define  REX3_DRAWMODE0_ENZPATTERN	0x00001000
#define  REX3_DRAWMODE0_ENLSPATTERN	0x00002000
#define  REX3_DRAWMODE0_LSADVLAST	0x00004000
#define  REX3_DRAWMODE0_LENGTH32	0x00008000
#define  REX3_DRAWMODE0_ZPOPAQUE	0x00010000

#define REX3_REG_LSMODE			0x0008

#define REX3_REG_LSPATTERN		0x000c

#define REX3_REG_LSPATSAVE		0x0010

#define REX3_REG_ZPATTERN		0x0014

#define REX3_REG_COLORBACK		0x0018

#define REX3_REG_XSTART			0x0100

#define REX3_REG_XYMOVE			0x0114
#define  REX3_XYMOVE_XSHIFT		16

#define REX3_REG_XSTARTI		0x0148

#define REX3_REG_XYSTARTI		0x0150
#define  REX3_XYSTARTI_XSHIFT		16

#define REX3_REG_XYENDI			0x0154
#define  REX3_XYENDI_XSHIFT		16

#define REX3_REG_WRMASK			0x0220

#define REX3_REG_COLORI			0x0224

#define REX3_REG_DCBMODE		0x0238
#define  REX3_DCBMODE_DW_MASK		0x00000003
#define   REX3_DCBMODE_DW_4		0x00000000
#define   REX3_DCBMODE_DW_1		0x00000001
#define   REX3_DCBMODE_DW_2		0x00000002
#define   REX3_DCBMODE_DW_3		0x00000003
#define  REX3_DCBMODE_ENDATAPACK	0x00000004
#define  REX3_DCBMODE_ENCRSINC		0x00000008
#define  REX3_DCBMODE_DCBCRS_MASK	0x00000070
#define   REX3_DCBMODE_DCBCRS_SHIFT	4
#define  REX3_DCBMODE_DCBADDR_MASK	0x00000780
#define   REX3_DCBMODE_DCBADDR_SHIFT	7
#define  REX3_DCBMODE_ENSYNCACK		0x00000800
#define  REX3_DCBMODE_ENASYNCACK	0x00001000
#define  REX3_DCBMODE_CSWIDTH_MASK	0x0003e000
#define  REX3_DCBMODE_CSWIDTH_SHIFT	13
#define  REX3_DCBMODE_CSHOLD_MASK	0x007c0000
#define  REX3_DCBMODE_CSHOLD_SHIFT	18
#define  REX3_DCBMODE_CSSETUP_MASK	0x0f800000
#define  REX3_DCBMODE_CSSETUP_SHIFT	23
#define  REX3_DCBMODE_SWAPENDIAN	0x10000000

#define REX3_REG_DCBDATA0		0x0240
#define REX3_REG_DCBDATA1		0x0244

/* Not really a register, but in the same space */
#define REX3_REG_GO			0x0800

#define REX3_REG_TOPSCAN		0x1320
#define REX3_REG_XYWIN			0x1324

#define REX3_REG_STATUS			0x1338
#define  REX3_STATUS_GFXBUSY		0x00000008

/* VC2 */

#define VC2_DCBCRS_INDEX		0
#define VC2_DCBCRS_IREG			1
#define VC2_DCBCRS_RAM			3

#define VC2_IREG_VIDEO_ENTRY		0x00

#define VC2_IREG_CURSOR_ENTRY		0x01

#define VC2_IREG_CURSOR_X		0x02

#define VC2_IREG_CURSOR_Y		0x03

#define VC2_IREG_SCANLINE_LENGTH	0x06

#define VC2_IREG_RAM_ADDRESS		0x07

#define VC2_IREG_CONTROL		0x10
#define  VC2_CONTROL_VINTR_ENABLE	0x0001
#define  VC2_CONTROL_DISPLAY_ENABLE	0x0002
#define  VC2_CONTROL_VTIMING_ENABLE	0x0004
#define  VC2_CONTROL_DID_ENABLE		0x0008
#define  VC2_CONTROL_CURSORFUNC_ENABLE	0x0010
#define  VC2_CONTROL_GENSYNC_ENABLE	0x0020
#define  VC2_CONTROL_INTERLACE		0x0040
#define  VC2_CONTROL_CURSOR_ENABLE	0x0080
#define  VC2_CONTROL_CROSSHAIR_CURSOR	0x0100
#define  VC2_CONTROL_LARGE_CURSOR	0x0200
#define  VC2_CONTROL_GENLOCK_1		0x0400

#define VC2_IREG_CONFIG			0x1f
#define VC2_IREG_CONFIG_SOFTRESET	0x01	/* active low */
#define VC2_IREG_CONFIG_SLOWCLOCK	0x02
#define VC2_IREG_CONFIG_CURSORERROR	0x04
#define VC2_IREG_CONFIG_DIDERROR	0x08
#define VC2_IREG_CONFIG_VTGERROR	0x10
#define VC2_IREG_CONFIG_REVISION	0x70

/* CMAP */

#define CMAP_DCBCRS_ADDRESS_LOW		0
#define CMAP_DCBCRS_ADDRESS_HIGH	1
#define CMAP_DCBCRS_PALETTE		2
#define CMAP_DCBCRS_REVISION		6

/* XMAP9 */

#define XMAP9_DCBCRS_CONFIG		0
#define  XMAP9_CONFIG_PUP_ENABLE	0x01
#define  XMAP9_CONFIG_ODD_PIXEL		0x02
#define  XMAP9_CONFIG_8BIT_SYSTEM	0x04
#define  XMAP9_CONFIG_SLOW_PCLK		0x08
#define  XMAP9_CONFIG_RGBMAP_CI		0x00
#define  XMAP9_CONFIG_RGBMAP_0		0x10
#define  XMAP9_CONFIG_RGBMAP_1		0x20
#define  XMAP9_CONFIG_RGBMAP_2		0x30
#define  XMAP9_CONFIG_EXPRESS_MODE	0x40
#define  XMAP9_CONFIG_VIDEO_ENABLE	0x80
#define XMAP9_DCBCRS_REVISION		1
#define XMAP9_DCBCRS_FIFOAVAIL		2
#define XMAP9_DCBCRS_CURSOR_CMAP	3
#define XMAP9_DCBCRS_PUP_CMAP		4
#define XMAP9_DCBCRS_MODE_SETUP		5
#define  XMAP9_MODE_GAMMA_BYPASS	0x000004
#define  XMAP9_MODE_PIXSIZE_8BPP	0x000400
#define XMAP9_DCBCRS_MODE_SELECT	7

/* DCB addresses */

#define NEWPORT_DCBADDR_VC2		0
#define NEWPORT_DCBADDR_CMAP_BOTH	1
#define NEWPORT_DCBADDR_CMAP_0		2
#define NEWPORT_DCBADDR_CMAP_1		3
#define NEWPORT_DCBADDR_XMAP_BOTH	4
#define NEWPORT_DCBADDR_XMAP_0		5
#define NEWPORT_DCBADDR_XMAP_1		6
#define NEWPORT_DCBADDR_RAMDAC		7
#define NEWPORT_DCBADDR_VIDEO_CC1	8
#define NEWPORT_DCBADDR_VIDEO_AB1	9

#endif
