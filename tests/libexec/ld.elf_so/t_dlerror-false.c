/*	$NetBSD: t_dlerror-false.c,v 1.3 2022/01/14 07:34:07 skrll Exp $	*/

/*
 * Copyright (c) 2009 The NetBSD Foundation, Inc.
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND
 * CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <dlfcn.h>
#include <link_elf.h>

#include "h_macros.h"

ATF_TC(rtld_dlerror_false);
ATF_TC_HEAD(rtld_dlerror_false, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "error set by dlopen persists past a successful dlopen call");
}

ATF_TC_BODY(rtld_dlerror_false, tc)
{
	void *handle, *sym;
	char *error;

	/*
	 *
	 * Test for dlerror() being set by a successful library open.
	 * Requires that the rpath be set to something that does not
	 * include libm.so.
	 */

	handle = dlopen("libm.so", RTLD_LAZY);
	error = dlerror();
	ATF_CHECK(error == NULL);
	ATF_CHECK(handle != NULL);

	sym = dlsym(handle, "sin");
	error = dlerror();
	ATF_CHECK(sym != NULL);
	ATF_CHECK(error == NULL);

	dlclose(handle);
	error = dlerror();

	ATF_CHECK(error == NULL);

}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, rtld_dlerror_false);

	return atf_no_error();
}
