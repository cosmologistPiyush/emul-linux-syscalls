/*	$NetBSD: moduleparam.h,v 1.11 2021/12/19 12:01:48 riastradh Exp $	*/

/*-
 * Copyright (c) 2013 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Taylor R. Campbell.
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

#ifndef _LINUX_MODULEPARAM_H_
#define _LINUX_MODULEPARAM_H_

#include <sys/types.h>

struct linux_module_param_info {
	const char *dname;	// Name used for description
	const char *name;	// Name for sysctl
	void *ptr;		// Pointer to variable value
	int type;		// MTYPE_ 
	mode_t mode;		// 600 (rw) or 400 (r)
};

#define MTYPE_int	0
#define MTYPE_bool	1
#define MTYPE_charp	2
#define MTYPE_uint	3

/*
 * In case of accidental cpp expansion, break glass to raise alarm and
 * reach antizombie chainsaw.
 */
#define	MTYPE__Bool	MTYPE_bool

#define	module_param_named(NAME, VAR, TYPE, MODE) \
static __attribute__((__used__)) struct linux_module_param_info info_ ## NAME = { \
	.dname = # NAME, \
	.name = # VAR, \
	.ptr = & VAR, \
	.type = MTYPE_ ## TYPE, \
	.mode = MODE, \
}; \
__link_set_add_data(linux_module_param_info, info_ ## NAME)

#define	module_param(VAR, TYPE, MODE)	module_param_named(VAR, VAR, TYPE, MODE)
#define	module_param_unsafe		module_param
#define	module_param_named_unsafe	module_param_named
#define	module_param_string(VAR, TYPE, SIZE, MODE)			      \
	CTASSERT(1)		/* XXX */

struct linux_module_param_desc {
	const char *name;
	const char *description;
};
#define	MODULE_PARM_DESC(PARAMETER, DESCRIPTION) \
static __attribute__((__used__)) \
const struct linux_module_param_desc PARAMETER ## _desc = { \
    .name = # PARAMETER, \
    .description = DESCRIPTION, \
}; \
__link_set_add_rodata(linux_module_param_desc, PARAMETER ## _desc)


#endif  /* _LINUX_MODULEPARAM_H_ */
