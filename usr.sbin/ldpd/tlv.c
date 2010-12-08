/* $NetBSD: tlv.c,v 1.1 2010/12/08 07:20:15 kefren Exp $ */

/*-
 * Copyright (c) 2010 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Mihai Chelaru <kefren@NetBSD.org>
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

#include <sys/stat.h>

#include <stdlib.h>
#include <strings.h>
#include <stdio.h>

#include "ldp.h"
#include "fsm.h"
#include "ldp_errors.h"
#include "tlv.h"

/* Reads and checks a tlv struct from a buffer */
struct hello_tlv *
get_hello_tlv(unsigned char *s, uint max)
{
	struct hello_tlv *t;

	/* Do we have at least Type + Length + MSG_ID ? */
	if (max <= TLV_TYPE_LENGTH + MSGID_SIZE)
		return NULL;

	t = (struct hello_tlv *) s;

	if (ntohs(t->type) != LDP_HELLO)
		return NULL;

	/* Does its size fit into max ? */
	if (ntohs(t->length) + TLV_TYPE_LENGTH > max)
		return NULL;

	t->type = ntohs(t->type);
	t->length = ntohs(t->length);
	t->messageid = ntohl(t->messageid);
	return t;
	/* We don't check for Common Hello Params here */
}

/* Prints out some information about TLV */
void 
debug_tlv(struct tlv * t)
{
	warnp("TLV type %.4X, Length %d, Message ID %.8X\n", ntohs(t->type),
	       ntohs(t->length), ntohs(t->messageid));
}
