/*	$NetBSD: irix_resource.h,v 1.1 2002/06/14 20:33:11 manu Exp $ */

/*-
 * Copyright (c) 2002 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Emmanuel Dreyfus.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the NetBSD
 *	Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _IRIX_RESOURCE_H_
#define _IRIX_RESOURCE_H_

/* From IRIX's <sys/resource.h> */
#define IRIX_RLIMIT_CPU		0
#define IRIX_RLIMIT_FSIZE	1
#define IRIX_RLIMIT_DATA	2
#define IRIX_RLIMIT_STACK	3
#define IRIX_RLIMIT_CORE	4
#define IRIX_RLIMIT_NOFILE	5
#define IRIX_RLIMIT_VMEM	6
#define IRIX_RLIMIT_RSS		7
#define IRIX_RLIMIT_PTHREAD	8
#define IRIX_RLIM_NLIMITS	9;

#define IRIX_RLIM64_INFINITY	0x7fffffffffffffffLL
#define IRIX_RLIM_INFINITY	0x7fffffff

typedef uint32_t irix_rlim_t;
typedef uint64_t irix_rlim64_t;

struct irix_rlimit {
	irix_rlim_t rlim_cur;
	irix_rlim_t rlim_max;
};

struct irix_rlimit64 {
	irix_rlim64_t rlim_cur;
	irix_rlim64_t rlim_max;
};

#endif /* _IRIX_RESOURCE_H_ */
