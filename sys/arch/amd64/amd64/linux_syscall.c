/*	$NetBSD: linux_syscall.c,v 1.2 2005/05/15 21:44:41 fvdl Exp $ */

/*-
 * Copyright (c) 2005 Emmanuel Dreyfus, all rights reserved.
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
 *	This product includes software developed by Emmanuel Dreyfus
 * 4. The name of the author may not be used to endorse or promote 
 *    products derived from this software without specific prior written 
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE THE AUTHOR AND CONTRIBUTORS ``AS IS'' 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS 
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "opt_compat_linux.h"
#include <sys/cdefs.h>

__KERNEL_RCSID(0, "$NetBSD: linux_syscall.c,v 1.2 2005/05/15 21:44:41 fvdl Exp $");

#include <sys/types.h>
#include <sys/param.h>
#include <sys/signal.h>
#include <sys/proc.h> 
 
#include <compat/linux/linux_syscall.h>
#include <compat/linux/common/linux_types.h>
#include <compat/linux/common/linux_errno.h>
#include <compat/linux/common/linux_signal.h>
#include <compat/linux/common/linux_siginfo.h>
#include <compat/linux/arch/amd64/linux_siginfo.h>
#include <compat/linux/arch/amd64/linux_syscall.h>
#include <compat/linux/arch/amd64/linux_machdep.h>

#define EMULNAME(x)     __CONCAT(linux_,x)
#define EMULNAMEU(x)    __CONCAT(LINUX_,x)

#include "syscall.c"
