/*	$NetBSD: smb_rq.h,v 1.1 2000/12/07 03:48:10 deberg Exp $	*/

/*
 * Copyright (c) 2000, Boris Popov
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _NETSMB_SMB_RQ_H_
#define	_NETSMB_SMB_RQ_H_

#ifndef MB_MSYSTEM
#include <sys/subr_mbuf.h>
#endif

#define	SMBR_ALLOCED		0x0001	/* structure was malloced */
#define	SMBR_SENT		0x0002	/* request successfully transmitted */
#define	SMBR_REXMIT		0x0004	/* request should be retransmitted */
#define	SMBR_INTR		0x0008	/* request interrupted */
#define	SMBR_RESTART		0x0010	/* request should be repeated if possible */
#define	SMBR_NORESTART		0x0020	/* request is not restartable */

#define SMBT2_ALLSENT		0x0001	/* all data and params are sent */
#define SMBT2_ALLRECV		0x0002	/* all data and params are received */
#define	SMBT2_ALLOCED		0x0004
#define	SMBT2_RESTART		0x0008
#define	SMBT2_NORESTART		0x0010

struct smb_conn;
struct smb_vc;
struct smb_t2rq;

struct smb_rq {
	struct smb_conn*sr_conn;
	struct smb_vc * sr_vc;
	struct smb_share*sr_share;
	u_short		sr_mid;
	struct mbdata	sr_rq;
	u_int8_t	sr_rqflags;
	u_int16_t	sr_rqflags2;
	u_char *	sr_wcount;
	u_short *	sr_bcount;
	struct mbdata	sr_rp;
	int		sr_flags;	/* SMBR_* */
	int		sr_rpsize;
	struct smb_cred*sr_cred;
	int		sr_timo;
	int		sr_rexmit;
	u_int16_t *	sr_rqtid;
	u_int16_t *	sr_rquid;
	u_int8_t	sr_errclass;
	u_int16_t	sr_serror;
	u_int32_t	sr_error;
	u_int8_t	sr_rpflags;
	u_int16_t	sr_rpflags2;
	u_int16_t	sr_rptid;
	u_int16_t	sr_rppid;
	u_int16_t	sr_rpuid;
	u_int16_t	sr_rpmid;
	struct simplelock sr_slock;	/* short term locks */
/*	struct smb_t2rq*sr_t2;*/
	TAILQ_ENTRY(smb_rq) sr_link;
};

struct smb_t2rq {
	u_int16_t	t2_setupcount;
	u_int16_t *	t2_setupdata;
	u_int16_t	t2_setup[2];	/* most of rqs has setupcount of 1 */
	u_int8_t	t2_maxscount;	/* max setup words to return */
	u_int16_t	t2_maxpcount;	/* max param bytes to return */
	u_int16_t	t2_maxdcount;	/* max data bytes to return */
	u_int16_t	t2_fid;		/* for T2 request */
	char *		t_name;		/* for T request, should be zero for T2 */
	int		t2_flags;	/* SMBT2_ */
	struct mbdata	t2_tparam;	/* parameters to transmit */
	struct mbdata	t2_tdata;	/* data to transmit */
	struct mbdata	t2_rparam;	/* received paramters */
	struct mbdata	t2_rdata;	/* received data */
	struct smb_cred*t2_cred;
	struct tnode *	t2_source;
	struct smb_rq *	t2_rq;
	struct smb_conn*t2_conn;
	struct smb_vc * t2_vc;
};

int  smb_rq_alloc(struct tnode *layer, u_char cmd,
	struct smb_cred *scred, struct smb_rq **rqpp);
int  smb_rq_init(struct smb_rq *rqp, struct tnode *layer, u_char cmd,
	struct smb_cred *scred);
void smb_rq_done(struct smb_rq *rqp);
int  smb_rq_getrequest(struct smb_rq *rqp, struct mbdata **mbpp);
int  smb_rq_getreply(struct smb_rq *rqp, struct mbdata **mbpp);
void smb_rq_wstart(struct smb_rq *rqp);
void smb_rq_wend(struct smb_rq *rqp);
void smb_rq_bstart(struct smb_rq *rqp);
void smb_rq_bend(struct smb_rq *rqp);
int  smb_rq_intr(struct smb_rq *rqp);
int  smb_rq_simple(struct smb_rq *rqp);

int  smb_t2_alloc(struct tnode *layer, u_short setup, struct smb_cred *scred,
	struct smb_t2rq **rqpp);
int  smb_t2_init(struct smb_t2rq *rqp, struct tnode *layer, u_short setup,
	struct smb_cred *scred);
void smb_t2_done(struct smb_t2rq *t2p);
int  smb_t2_request(struct smb_t2rq *t2p);

#endif /* !_NETSMB_SMB_RQ_H_ */
