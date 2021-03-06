/*	$NetBSD: alaw.c,v 1.4 2021/07/21 06:35:44 skrll Exp $	*/

/*
 * Copyright (C) 2018 Tetsuya Isaki. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: alaw.c,v 1.4 2021/07/21 06:35:44 skrll Exp $");

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/device.h>
#include <dev/audio/audiovar.h>
#include <dev/audio/mulaw.h>

static const uint16_t alaw_to_slinear16[256] = {
	0xea80, 0xeb80, 0xe880, 0xe980, 0xee80, 0xef80, 0xec80, 0xed80,
	0xe280, 0xe380, 0xe080, 0xe180, 0xe680, 0xe780, 0xe480, 0xe580,
	0xf540, 0xf5c0, 0xf440, 0xf4c0, 0xf740, 0xf7c0, 0xf640, 0xf6c0,
	0xf140, 0xf1c0, 0xf040, 0xf0c0, 0xf340, 0xf3c0, 0xf240, 0xf2c0,
	0xaa00, 0xae00, 0xa200, 0xa600, 0xba00, 0xbe00, 0xb200, 0xb600,
	0x8a00, 0x8e00, 0x8200, 0x8600, 0x9a00, 0x9e00, 0x9200, 0x9600,
	0xd500, 0xd700, 0xd100, 0xd300, 0xdd00, 0xdf00, 0xd900, 0xdb00,
	0xc500, 0xc700, 0xc100, 0xc300, 0xcd00, 0xcf00, 0xc900, 0xcb00,
	0xfea8, 0xfeb8, 0xfe88, 0xfe98, 0xfee8, 0xfef8, 0xfec8, 0xfed8,
	0xfe28, 0xfe38, 0xfe08, 0xfe18, 0xfe68, 0xfe78, 0xfe48, 0xfe58,
	0xffa8, 0xffb8, 0xff88, 0xff98, 0xffe8, 0xfff8, 0xffc8, 0xffd8,
	0xff28, 0xff38, 0xff08, 0xff18, 0xff68, 0xff78, 0xff48, 0xff58,
	0xfaa0, 0xfae0, 0xfa20, 0xfa60, 0xfba0, 0xfbe0, 0xfb20, 0xfb60,
	0xf8a0, 0xf8e0, 0xf820, 0xf860, 0xf9a0, 0xf9e0, 0xf920, 0xf960,
	0xfd50, 0xfd70, 0xfd10, 0xfd30, 0xfdd0, 0xfdf0, 0xfd90, 0xfdb0,
	0xfc50, 0xfc70, 0xfc10, 0xfc30, 0xfcd0, 0xfcf0, 0xfc90, 0xfcb0,
	0x1580, 0x1480, 0x1780, 0x1680, 0x1180, 0x1080, 0x1380, 0x1280,
	0x1d80, 0x1c80, 0x1f80, 0x1e80, 0x1980, 0x1880, 0x1b80, 0x1a80,
	0x0ac0, 0x0a40, 0x0bc0, 0x0b40, 0x08c0, 0x0840, 0x09c0, 0x0940,
	0x0ec0, 0x0e40, 0x0fc0, 0x0f40, 0x0cc0, 0x0c40, 0x0dc0, 0x0d40,
	0x5600, 0x5200, 0x5e00, 0x5a00, 0x4600, 0x4200, 0x4e00, 0x4a00,
	0x7600, 0x7200, 0x7e00, 0x7a00, 0x6600, 0x6200, 0x6e00, 0x6a00,
	0x2b00, 0x2900, 0x2f00, 0x2d00, 0x2300, 0x2100, 0x2700, 0x2500,
	0x3b00, 0x3900, 0x3f00, 0x3d00, 0x3300, 0x3100, 0x3700, 0x3500,
	0x0158, 0x0148, 0x0178, 0x0168, 0x0118, 0x0108, 0x0138, 0x0128,
	0x01d8, 0x01c8, 0x01f8, 0x01e8, 0x0198, 0x0188, 0x01b8, 0x01a8,
	0x0058, 0x0048, 0x0078, 0x0068, 0x0018, 0x0008, 0x0038, 0x0028,
	0x00d8, 0x00c8, 0x00f8, 0x00e8, 0x0098, 0x0088, 0x00b8, 0x00a8,
	0x0560, 0x0520, 0x05e0, 0x05a0, 0x0460, 0x0420, 0x04e0, 0x04a0,
	0x0760, 0x0720, 0x07e0, 0x07a0, 0x0660, 0x0620, 0x06e0, 0x06a0,
	0x02b0, 0x0290, 0x02f0, 0x02d0, 0x0230, 0x0210, 0x0270, 0x0250,
	0x03b0, 0x0390, 0x03f0, 0x03d0, 0x0330, 0x0310, 0x0370, 0x0350,
};

static const uint8_t slinear8_to_alaw[256] = {
	0xd5, 0xc5, 0xf5, 0xfd, 0xe5, 0xe1, 0xed, 0xe9,
	0x95, 0x97, 0x91, 0x93, 0x9d, 0x9f, 0x99, 0x9b,
	0x85, 0x84, 0x87, 0x86, 0x81, 0x80, 0x83, 0x82,
	0x8d, 0x8c, 0x8f, 0x8e, 0x89, 0x88, 0x8b, 0x8a,
	0xb5, 0xb5, 0xb4, 0xb4, 0xb7, 0xb7, 0xb6, 0xb6,
	0xb1, 0xb1, 0xb0, 0xb0, 0xb3, 0xb3, 0xb2, 0xb2,
	0xbd, 0xbd, 0xbc, 0xbc, 0xbf, 0xbf, 0xbe, 0xbe,
	0xb9, 0xb9, 0xb8, 0xb8, 0xbb, 0xbb, 0xba, 0xba,
	0xa5, 0xa5, 0xa5, 0xa5, 0xa4, 0xa4, 0xa4, 0xa4,
	0xa7, 0xa7, 0xa7, 0xa7, 0xa6, 0xa6, 0xa6, 0xa6,
	0xa1, 0xa1, 0xa1, 0xa1, 0xa0, 0xa0, 0xa0, 0xa0,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa2, 0xa2, 0xa2, 0xa2,
	0xad, 0xad, 0xad, 0xad, 0xac, 0xac, 0xac, 0xac,
	0xaf, 0xaf, 0xaf, 0xaf, 0xae, 0xae, 0xae, 0xae,
	0xa9, 0xa9, 0xa9, 0xa9, 0xa8, 0xa8, 0xa8, 0xa8,
	0xab, 0xab, 0xab, 0xab, 0xaa, 0xaa, 0xaa, 0xaa,
	0x2a, 0x2a, 0x2a, 0x2a, 0x2b, 0x2b, 0x2b, 0x2b,
	0x28, 0x28, 0x28, 0x28, 0x29, 0x29, 0x29, 0x29,
	0x2e, 0x2e, 0x2e, 0x2e, 0x2f, 0x2f, 0x2f, 0x2f,
	0x2c, 0x2c, 0x2c, 0x2c, 0x2d, 0x2d, 0x2d, 0x2d,
	0x22, 0x22, 0x22, 0x22, 0x23, 0x23, 0x23, 0x23,
	0x20, 0x20, 0x20, 0x20, 0x21, 0x21, 0x21, 0x21,
	0x26, 0x26, 0x26, 0x26, 0x27, 0x27, 0x27, 0x27,
	0x24, 0x24, 0x24, 0x24, 0x25, 0x25, 0x25, 0x25,
	0x3a, 0x3a, 0x3b, 0x3b, 0x38, 0x38, 0x39, 0x39,
	0x3e, 0x3e, 0x3f, 0x3f, 0x3c, 0x3c, 0x3d, 0x3d,
	0x32, 0x32, 0x33, 0x33, 0x30, 0x30, 0x31, 0x31,
	0x36, 0x36, 0x37, 0x37, 0x34, 0x34, 0x35, 0x35,
	0x0a, 0x0b, 0x08, 0x09, 0x0e, 0x0f, 0x0c, 0x0d,
	0x02, 0x03, 0x00, 0x01, 0x06, 0x07, 0x04, 0x05,
	0x1a, 0x18, 0x1e, 0x1c, 0x12, 0x10, 0x16, 0x14,
	0x6a, 0x6e, 0x62, 0x66, 0x7a, 0x72, 0x4a, 0x5a,
};

/*
 * audio_alaw_to_internal:
 *	This filter performs conversion from A-law to internal format.
 */
void
audio_alaw_to_internal(audio_filter_arg_t *arg)
{
	const uint8_t *s;
	aint_t *d;
	u_int sample_count;
	u_int i;

	DIAGNOSTIC_filter_arg(arg);
	KASSERT(arg->srcfmt->encoding == AUDIO_ENCODING_ALAW);
	KASSERT(arg->srcfmt->stride == 8);
	KASSERT(arg->srcfmt->precision == 8);
	KASSERT(audio_format2_is_internal(arg->dstfmt));
	KASSERT(arg->srcfmt->channels == arg->dstfmt->channels);

	s = arg->src;
	d = arg->dst;
	sample_count = arg->count * arg->srcfmt->channels;

	for (i = 0; i < sample_count; i++) {
		aint_t val;
		val = alaw_to_slinear16[*s++];
		val <<= AUDIO_INTERNAL_BITS - 16;
		*d++ = val;
	}
}

/*
 * audio_internal_to_alaw:
 *	This filter performs conversion from internal format to A-law.
 */
void
audio_internal_to_alaw(audio_filter_arg_t *arg)
{
	const aint_t *s;
	uint8_t *d;
	u_int sample_count;
	u_int i;

	DIAGNOSTIC_filter_arg(arg);
	KASSERT(arg->dstfmt->encoding == AUDIO_ENCODING_ALAW);
	KASSERT(arg->dstfmt->stride == 8);
	KASSERT(arg->dstfmt->precision == 8);
	KASSERT(audio_format2_is_internal(arg->srcfmt));
	KASSERT(arg->srcfmt->channels == arg->dstfmt->channels);

	s = arg->src;
	d = arg->dst;
	sample_count = arg->count * arg->srcfmt->channels;

	for (i = 0; i < sample_count; i++) {
		uint8_t val;
		val = (*s++) >> (AUDIO_INTERNAL_BITS - 8);
		*d++ = slinear8_to_alaw[val];
	}
}
