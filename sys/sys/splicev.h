/*	$NetBSD: splicev.h 2022/07/21 TIME NAME $	*/

/*-
 * Copyright (c) 2009 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Andrew Doran.
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
 *
 *
 */

#ifndef _SYS_SPLICEV_H_
#define _SYS_SPLICEV_H_

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/uio.h>

struct sf_hdtr {
  struct iovec *hdr;
  size_t hdrlen;
  struct iovec *trlr;
  size_t trlen;
};

struct sendfile_args {
  /* all the args are from FreeBSD */
  struct sf_hdtr *hdtr;
  off_t *sbytes;
  int flags;
};

struct splice_args {
  off_t off_out;
  unsigned int flags;
};

enum action { SPLICE, SENDFILE };

struct spliceops {
  enum action choice;
  union {
    struct splice_args *spargs;
    struct sendfile_args *sfargs;
  } op;
};

#define spliceargs		op.spargs
#define sendfileargs	op.sfargs
#define sp_offset		spliceargs->out_off
#define sp_flags		spliceargs->flags
#define sf_shdtr		sendfileargs->hdtr
#define sf_sbytes		sendfileargs->sbytes
#define sf_flags		sendfileargs.flags

/*TODO define flags */

#endif
