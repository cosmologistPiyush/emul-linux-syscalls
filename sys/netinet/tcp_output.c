/*	$NetBSD: tcp_output.c,v 1.47 1999/01/20 03:39:54 thorpej Exp $	*/

/*-
 * Copyright (c) 1997, 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe and Kevin M. Lahey of the Numerical Aerospace Simulation
 * Facility, NASA Ames Research Center.
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

/*
 * Copyright (c) 1982, 1986, 1988, 1990, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)tcp_output.c	8.4 (Berkeley) 5/24/95
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/errno.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#define	TCPOUTFLAGS
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_debug.h>

#ifdef notyet
extern struct mbuf *m_copypack();
#endif

#define MAX_TCPOPTLEN	32	/* max # bytes that go in options */

/*
 * Knob to enable Congestion Window Monitoring, and control the
 * the burst size it allows.  Default burst is 4 packets, per
 * the Internet draft.
 */
int	tcp_cwm = 0;
int	tcp_cwm_burstsize = 4;

static __inline void tcp_segsize __P((struct tcpcb *, int *, int *));
static __inline void
tcp_segsize(tp, txsegsizep, rxsegsizep)
	struct tcpcb *tp;
	int *txsegsizep, *rxsegsizep;
{
	struct inpcb *inp = tp->t_inpcb;
	struct rtentry *rt;
	struct ifnet *ifp;
	int size;

	if ((rt = in_pcbrtentry(inp)) == NULL) {
		size = tcp_mssdflt;
		goto out;
	}

	ifp = rt->rt_ifp;

	if (rt->rt_rmx.rmx_mtu != 0)
		size = rt->rt_rmx.rmx_mtu - sizeof(struct tcpiphdr);
	else if (ip_mtudisc || in_localaddr(inp->inp_faddr) ||
		 ifp->if_flags & IFF_LOOPBACK)
		size = ifp->if_mtu - sizeof(struct tcpiphdr);
	else
		size = tcp_mssdflt;
	size -= (tcp_optlen(tp) + ip_optlen(tp->t_inpcb));

 out:
	*txsegsizep = min(tp->t_peermss, size);
	*rxsegsizep = min(tp->t_ourmss, size);

	if (*txsegsizep != tp->t_segsz) {
		/*
		 * If the new segment size is larger, we don't want to 
		 * mess up the congestion window, but if it is smaller
		 * we'll have to reduce the congestion window to ensure
		 * that we don't get into trouble with initial windows
		 * and the rest.  In any case, if the segment size
		 * has changed, chances are the path has, too, and
		 * our congestion window will be different.
		 */
		if (*txsegsizep < tp->t_segsz) {
			tp->snd_cwnd = max((tp->snd_cwnd / tp->t_segsz) 
					   * *txsegsizep, *txsegsizep);
			tp->snd_ssthresh = max((tp->snd_ssthresh / tp->t_segsz) 
						* *txsegsizep, *txsegsizep);
		}
		tp->t_segsz = *txsegsizep;
	}
}

/*
 * Tcp output routine: figure out what should be sent and send it.
 */
int
tcp_output(tp)
	register struct tcpcb *tp;
{
	struct socket *so = tp->t_inpcb->inp_socket;
	struct route *ro = &tp->t_inpcb->inp_route;
	struct rtentry *rt;
	struct sockaddr_in *dst;
	long len, win;
	int off, flags, error;
	register struct mbuf *m;
	register struct tcpiphdr *ti;
	u_char opt[MAX_TCPOPTLEN];
	unsigned optlen, hdrlen;
	int idle, sendalot, txsegsize, rxsegsize;
	int maxburst = TCP_MAXBURST;

	tcp_segsize(tp, &txsegsize, &rxsegsize);

	idle = (tp->snd_max == tp->snd_una);

	/*
	 * Restart Window computation.  From draft-floyd-incr-init-win-03:
	 *
	 *	Optionally, a TCP MAY set the restart window to the
	 *	minimum of the value used for the initial window and
	 *	the current value of cwnd (in other words, using a
	 *	larger value for the restart window should never increase
	 *	the size of cwnd).
	 */
	if (tcp_cwm) {
		/*
		 * Hughes/Touch/Heidemann Congestion Window Monitoring.
		 * Count the number of packets currently pending
		 * acknowledgement, and limit our congestion window
		 * to a pre-determined allowed burst size plus that count.
		 * This prevents bursting once all pending packets have
		 * been acknowledged (i.e. transmission is idle).
		 *
		 * XXX Link this to Initial Window?
		 */
		tp->snd_cwnd = min(tp->snd_cwnd,
		    (tcp_cwm_burstsize * txsegsize) +
		    (tp->snd_nxt - tp->snd_una));
	} else {
		if (idle && tp->t_idle >= tp->t_rxtcur) {
			/*
			 * We have been idle for "a while" and no acks are
			 * expected to clock out any data we send --
			 * slow start to get ack "clock" running again.
			 */
			tp->snd_cwnd = min(tp->snd_cwnd,
			    TCP_INITIAL_WINDOW(tcp_init_win, txsegsize));
		}
	}

again:
	/*
	 * Determine length of data that should be transmitted, and
	 * flags that should be used.  If there is some data or critical
	 * controls (SYN, RST) to send, then transmit; otherwise,
	 * investigate further.
	 */
	sendalot = 0;
	off = tp->snd_nxt - tp->snd_una;
	win = min(tp->snd_wnd, tp->snd_cwnd);

	flags = tcp_outflags[tp->t_state];
	/*
	 * If in persist timeout with window of 0, send 1 byte.
	 * Otherwise, if window is small but nonzero
	 * and timer expired, we will send what we can
	 * and go to transmit state.
	 */
	if (tp->t_force) {
		if (win == 0) {
			/*
			 * If we still have some data to send, then
			 * clear the FIN bit.  Usually this would
			 * happen below when it realizes that we
			 * aren't sending all the data.  However,
			 * if we have exactly 1 byte of unset data,
			 * then it won't clear the FIN bit below,
			 * and if we are in persist state, we wind
			 * up sending the packet without recording
			 * that we sent the FIN bit.
			 *
			 * We can't just blindly clear the FIN bit,
			 * because if we don't have any more data
			 * to send then the probe will be the FIN
			 * itself.
			 */
			if (off < so->so_snd.sb_cc)
				flags &= ~TH_FIN;
			win = 1;
		} else {
			TCP_TIMER_DISARM(tp, TCPT_PERSIST);
			tp->t_rxtshift = 0;
		}
	}

	if (win < so->so_snd.sb_cc) {
		len = win - off;
		flags &= ~TH_FIN;
	} else
		len = so->so_snd.sb_cc - off;

	if (len < 0) {
		/*
		 * If FIN has been sent but not acked,
		 * but we haven't been called to retransmit,
		 * len will be -1.  Otherwise, window shrank
		 * after we sent into it.  If window shrank to 0,
		 * cancel pending retransmit, pull snd_nxt back
		 * to (closed) window, and set the persist timer
		 * if it isn't already going.  If the window didn't
		 * close completely, just wait for an ACK.
		 *
		 * If we have a pending FIN, either it has already been
		 * transmitted or it is outside the window, so drop it.
		 * If the FIN has been transmitted, but this is not a
		 * retransmission, then len must be -1.  Therefore we also
		 * prevent here the sending of `gratuitous FINs'.  This
		 * eliminates the need to check for that case below (e.g.
		 * to back up snd_nxt before the FIN so that the sequence
		 * number is correct).
		 */
		len = 0;
		flags &= ~TH_FIN;
		if (win == 0) {
			TCP_TIMER_DISARM(tp, TCPT_REXMT);
			tp->t_rxtshift = 0;
			tp->snd_nxt = tp->snd_una;
			if (TCP_TIMER_ISARMED(tp, TCPT_PERSIST) == 0)
				tcp_setpersist(tp);
		}
	}
	if (len > txsegsize) {
		len = txsegsize;
		flags &= ~TH_FIN;
		sendalot = 1;
	}

	win = sbspace(&so->so_rcv);

	/*
	 * Sender silly window avoidance.  If connection is idle
	 * and can send all data, a maximum segment,
	 * at least a maximum default-size segment do it,
	 * or are forced, do it; otherwise don't bother.
	 * If peer's buffer is tiny, then send
	 * when window is at least half open.
	 * If retransmitting (possibly after persist timer forced us
	 * to send into a small window), then must resend.
	 */
	if (len) {
		if (len == txsegsize)
			goto send;
		if ((so->so_state & SS_MORETOCOME) == 0 &&
		    ((idle || tp->t_flags & TF_NODELAY) &&
		     len + off >= so->so_snd.sb_cc))
			goto send;
		if (tp->t_force)
			goto send;
		if (len >= tp->max_sndwnd / 2)
			goto send;
		if (SEQ_LT(tp->snd_nxt, tp->snd_max))
			goto send;
	}

	/*
	 * Compare available window to amount of window known to peer
	 * (as advertised window less next expected input).  If the
	 * difference is at least twice the size of the largest segment
	 * we expect to receive (i.e. two segments) or at least 50% of
	 * the maximum possible window, then want to send a window update
	 * to peer.
	 */
	if (win > 0) {
		/* 
		 * "adv" is the amount we can increase the window,
		 * taking into account that we are limited by
		 * TCP_MAXWIN << tp->rcv_scale.
		 */
		long adv = min(win, (long)TCP_MAXWIN << tp->rcv_scale) -
			(tp->rcv_adv - tp->rcv_nxt);

		if (adv >= (long) (2 * rxsegsize))
			goto send;
		if (2 * adv >= (long) so->so_rcv.sb_hiwat)
			goto send;
	}

	/*
	 * Send if we owe peer an ACK.
	 */
	if (tp->t_flags & TF_ACKNOW)
		goto send;
	if (flags & (TH_SYN|TH_FIN|TH_RST))
		goto send;
	if (SEQ_GT(tp->snd_up, tp->snd_una))
		goto send;

	/*
	 * TCP window updates are not reliable, rather a polling protocol
	 * using ``persist'' packets is used to insure receipt of window
	 * updates.  The three ``states'' for the output side are:
	 *	idle			not doing retransmits or persists
	 *	persisting		to move a small or zero window
	 *	(re)transmitting	and thereby not persisting
	 *
	 * tp->t_timer[TCPT_PERSIST]
	 *	is set when we are in persist state.
	 * tp->t_force
	 *	is set when we are called to send a persist packet.
	 * tp->t_timer[TCPT_REXMT]
	 *	is set when we are retransmitting
	 * The output side is idle when both timers are zero.
	 *
	 * If send window is too small, there is data to transmit, and no
	 * retransmit or persist is pending, then go to persist state.
	 * If nothing happens soon, send when timer expires:
	 * if window is nonzero, transmit what we can,
	 * otherwise force out a byte.
	 */
	if (so->so_snd.sb_cc && TCP_TIMER_ISARMED(tp, TCPT_REXMT) == 0 &&
	    TCP_TIMER_ISARMED(tp, TCPT_PERSIST) == 0) {
		tp->t_rxtshift = 0;
		tcp_setpersist(tp);
	}

	/*
	 * No reason to send a segment, just return.
	 */
	return (0);

send:
	/*
	 * Before ESTABLISHED, force sending of initial options
	 * unless TCP set not to do any options.
	 * NOTE: we assume that the IP/TCP header plus TCP options
	 * always fit in a single mbuf, leaving room for a maximum
	 * link header, i.e.
	 *	max_linkhdr + sizeof (struct tcpiphdr) + optlen <= MHLEN
	 */
	optlen = 0;
	hdrlen = sizeof (struct tcpiphdr);
	if (flags & TH_SYN) {
		struct rtentry *rt = in_pcbrtentry(tp->t_inpcb);

		tp->snd_nxt = tp->iss;
		tp->t_ourmss = tcp_mss_to_advertise(rt != NULL ? 
						    rt->rt_ifp : NULL);
		if ((tp->t_flags & TF_NOOPT) == 0) {
			opt[0] = TCPOPT_MAXSEG;
			opt[1] = 4;
			opt[2] = (tp->t_ourmss >> 8) & 0xff;
			opt[3] = tp->t_ourmss & 0xff;
			optlen = 4;
	 
			if ((tp->t_flags & TF_REQ_SCALE) &&
			    ((flags & TH_ACK) == 0 ||
			    (tp->t_flags & TF_RCVD_SCALE))) {
				*((u_int32_t *) (opt + optlen)) = htonl(
					TCPOPT_NOP << 24 |
					TCPOPT_WINDOW << 16 |
					TCPOLEN_WINDOW << 8 |
					tp->request_r_scale);
				optlen += 4;
			}
		}
 	}
 
 	/*
	 * Send a timestamp and echo-reply if this is a SYN and our side 
	 * wants to use timestamps (TF_REQ_TSTMP is set) or both our side
	 * and our peer have sent timestamps in our SYN's.
 	 */
 	if ((tp->t_flags & (TF_REQ_TSTMP|TF_NOOPT)) == TF_REQ_TSTMP &&
 	     (flags & TH_RST) == 0 &&
 	    ((flags & (TH_SYN|TH_ACK)) == TH_SYN ||
	     (tp->t_flags & TF_RCVD_TSTMP))) {
		u_int32_t *lp = (u_int32_t *)(opt + optlen);
 
 		/* Form timestamp option as shown in appendix A of RFC 1323. */
 		*lp++ = htonl(TCPOPT_TSTAMP_HDR);
 		*lp++ = htonl(tcp_now);
 		*lp   = htonl(tp->ts_recent);
 		optlen += TCPOLEN_TSTAMP_APPA;
 	}

 	hdrlen += optlen;
 
#ifdef DIAGNOSTIC
	if (len > txsegsize)
		panic("tcp data to be sent is larger than segment");
 	if (max_linkhdr + hdrlen > MHLEN)
		panic("tcphdr too big");
#endif

	/*
	 * Grab a header mbuf, attaching a copy of data to
	 * be transmitted, and initialize the header from
	 * the template for sends on this connection.
	 */
	if (len) {
		if (tp->t_force && len == 1)
			tcpstat.tcps_sndprobe++;
		else if (SEQ_LT(tp->snd_nxt, tp->snd_max)) {
			tcpstat.tcps_sndrexmitpack++;
			tcpstat.tcps_sndrexmitbyte += len;
		} else {
			tcpstat.tcps_sndpack++;
			tcpstat.tcps_sndbyte += len;
		}
#ifdef notyet
		if ((m = m_copypack(so->so_snd.sb_mb, off,
		    (int)len, max_linkhdr + hdrlen)) == 0) {
			error = ENOBUFS;
			goto out;
		}
		/*
		 * m_copypack left space for our hdr; use it.
		 */
		m->m_len += hdrlen;
		m->m_data -= hdrlen;
#else
		MGETHDR(m, M_DONTWAIT, MT_HEADER);
		if (m == NULL) {
			error = ENOBUFS;
			goto out;
		}
		m->m_data += max_linkhdr;
		m->m_len = hdrlen;
		if (len <= MHLEN - hdrlen - max_linkhdr) {
			m_copydata(so->so_snd.sb_mb, off, (int) len,
			    mtod(m, caddr_t) + hdrlen);
			m->m_len += len;
		} else {
			m->m_next = m_copy(so->so_snd.sb_mb, off, (int) len);
			if (m->m_next == 0) {
				m_freem(m);
				error = ENOBUFS;
				goto out;
			}
		}
#endif
		/*
		 * If we're sending everything we've got, set PUSH.
		 * (This will keep happy those implementations which only
		 * give data to the user when a buffer fills or
		 * a PUSH comes in.)
		 */
		if (off + len == so->so_snd.sb_cc)
			flags |= TH_PUSH;
	} else {
		if (tp->t_flags & TF_ACKNOW)
			tcpstat.tcps_sndacks++;
		else if (flags & (TH_SYN|TH_FIN|TH_RST))
			tcpstat.tcps_sndctrl++;
		else if (SEQ_GT(tp->snd_up, tp->snd_una))
			tcpstat.tcps_sndurg++;
		else
			tcpstat.tcps_sndwinup++;

		MGETHDR(m, M_DONTWAIT, MT_HEADER);
		if (m == NULL) {
			error = ENOBUFS;
			goto out;
		}
		m->m_data += max_linkhdr;
		m->m_len = hdrlen;
	}
	m->m_pkthdr.rcvif = (struct ifnet *)0;
	ti = mtod(m, struct tcpiphdr *);
	if (tp->t_template == 0)
		panic("tcp_output");
	bcopy((caddr_t)tp->t_template, (caddr_t)ti, sizeof (struct tcpiphdr));

	/*
	 * If we are doing retransmissions, then snd_nxt will
	 * not reflect the first unsent octet.  For ACK only
	 * packets, we do not want the sequence number of the
	 * retransmitted packet, we want the sequence number
	 * of the next unsent octet.  So, if there is no data
	 * (and no SYN or FIN), use snd_max instead of snd_nxt
	 * when filling in ti_seq.  But if we are in persist
	 * state, snd_max might reflect one byte beyond the
	 * right edge of the window, so use snd_nxt in that
	 * case, since we know we aren't doing a retransmission.
	 * (retransmit and persist are mutually exclusive...)
	 */
	if (len || (flags & (TH_SYN|TH_FIN)) ||
	    TCP_TIMER_ISARMED(tp, TCPT_PERSIST))
		ti->ti_seq = htonl(tp->snd_nxt);
	else
		ti->ti_seq = htonl(tp->snd_max);
	ti->ti_ack = htonl(tp->rcv_nxt);
	if (optlen) {
		bcopy((caddr_t)opt, (caddr_t)(ti + 1), optlen);
		ti->ti_off = (sizeof (struct tcphdr) + optlen) >> 2;
	}
	ti->ti_flags = flags;
	/*
	 * Calculate receive window.  Don't shrink window,
	 * but avoid silly window syndrome.
	 */
	if (win < (long)(so->so_rcv.sb_hiwat / 4) && win < (long)rxsegsize)
		win = 0;
	if (win > (long)TCP_MAXWIN << tp->rcv_scale)
		win = (long)TCP_MAXWIN << tp->rcv_scale;
	if (win < (long)(tp->rcv_adv - tp->rcv_nxt))
		win = (long)(tp->rcv_adv - tp->rcv_nxt);
	ti->ti_win = htons((u_int16_t) (win>>tp->rcv_scale));
	if (SEQ_GT(tp->snd_up, tp->snd_nxt)) {
		u_int32_t urp = tp->snd_up - tp->snd_nxt;
		if (urp > IP_MAXPACKET)
			urp = IP_MAXPACKET;
		ti->ti_urp = htons((u_int16_t)urp);
		ti->ti_flags |= TH_URG;
	} else
		/*
		 * If no urgent pointer to send, then we pull
		 * the urgent pointer to the left edge of the send window
		 * so that it doesn't drift into the send window on sequence
		 * number wraparound.
		 */
		tp->snd_up = tp->snd_una;		/* drag it along */

	/*
	 * Put TCP length in extended header, and then
	 * checksum extended header and data.
	 */
	if (len + optlen)
		ti->ti_len = htons((u_int16_t)(sizeof (struct tcphdr) +
		    optlen + len));
	ti->ti_sum = in_cksum(m, (int)(hdrlen + len));

	/*
	 * In transmit state, time the transmission and arrange for
	 * the retransmit.  In persist state, just set snd_max.
	 */
	if (tp->t_force == 0 || TCP_TIMER_ISARMED(tp, TCPT_PERSIST) == 0) {
		tcp_seq startseq = tp->snd_nxt;

		/*
		 * Advance snd_nxt over sequence space of this segment.
		 * There are no states in which we send both a SYN and a FIN,
		 * so we collapse the tests for these flags.
		 */
		if (flags & (TH_SYN|TH_FIN))
			tp->snd_nxt++;
		tp->snd_nxt += len;
		if (SEQ_GT(tp->snd_nxt, tp->snd_max)) {
			tp->snd_max = tp->snd_nxt;
			/*
			 * Time this transmission if not a retransmission and
			 * not currently timing anything.
			 */
			if (tp->t_rtt == 0) {
				tp->t_rtt = 1;
				tp->t_rtseq = startseq;
				tcpstat.tcps_segstimed++;
			}
		}

		/*
		 * Set retransmit timer if not currently set,
		 * and not doing an ack or a keep-alive probe.
		 * Initial value for retransmit timer is smoothed
		 * round-trip time + 2 * round-trip time variance.
		 * Initialize shift counter which is used for backoff
		 * of retransmit time.
		 */
		if (TCP_TIMER_ISARMED(tp, TCPT_REXMT) == 0 &&
		    tp->snd_nxt != tp->snd_una) {
			TCP_TIMER_ARM(tp, TCPT_REXMT, tp->t_rxtcur);
			if (TCP_TIMER_ISARMED(tp, TCPT_PERSIST)) {
				TCP_TIMER_DISARM(tp, TCPT_PERSIST);
				tp->t_rxtshift = 0;
			}
		}
	} else
		if (SEQ_GT(tp->snd_nxt + len, tp->snd_max))
			tp->snd_max = tp->snd_nxt + len;

	/*
	 * Trace.
	 */
	if (so->so_options & SO_DEBUG)
		tcp_trace(TA_OUTPUT, tp->t_state, tp, ti, 0);

	/*
	 * Fill in IP length and desired time to live and
	 * send to IP level.  There should be a better way
	 * to handle ttl and tos; we could keep them in
	 * the template, but need a way to checksum without them.
	 */
	m->m_pkthdr.len = hdrlen + len;

	((struct ip *)ti)->ip_len = m->m_pkthdr.len;
	((struct ip *)ti)->ip_ttl = tp->t_inpcb->inp_ip.ip_ttl;	/* XXX */
	((struct ip *)ti)->ip_tos = tp->t_inpcb->inp_ip.ip_tos;	/* XXX */

	/*
	 * If we're doing Path MTU discovery, we need to set DF unless
	 * the route's MTU is locked.  If we lack a route, we need to
	 * look it up now.
	 *
	 * ip_output() could do this for us, but it's convenient to just
	 * do it here unconditionally.
	 */
	if ((rt = ro->ro_rt) == NULL || (rt->rt_flags & RTF_UP) == 0) {
		if (ro->ro_rt != NULL) {
			RTFREE(ro->ro_rt);
			ro->ro_rt = NULL;
		}
		dst = satosin(&ro->ro_dst);
		dst->sin_family = AF_INET;
		dst->sin_len = sizeof(*dst);
		dst->sin_addr = tp->t_inpcb->inp_faddr;
		rtalloc(ro);
		if ((rt = ro->ro_rt) == NULL) {
			m_freem(m);
			ipstat.ips_noroute++;
			error = EHOSTUNREACH;
			goto out;
		}
	}
	if (ip_mtudisc != 0 && (rt->rt_rmx.rmx_locks & RTV_MTU) == 0)
		((struct ip *)ti)->ip_off |= IP_DF;

#if BSD >= 43
	error = ip_output(m, tp->t_inpcb->inp_options, ro,
	    so->so_options & SO_DONTROUTE, 0);
#else
	error = ip_output(m, (struct mbuf *)0, ro,
	    so->so_options & SO_DONTROUTE);
#endif
	if (error) {
out:
		if (error == ENOBUFS) {
			tcp_quench(tp->t_inpcb, 0);
			return (0);
		}
		if ((error == EHOSTUNREACH || error == ENETDOWN)
		    && TCPS_HAVERCVDSYN(tp->t_state)) {
			tp->t_softerror = error;
			return (0);
		}
		return (error);
	}
	tcpstat.tcps_sndtotal++;
	if (tp->t_flags & TF_DELACK)
		tcpstat.tcps_delack++;

	/*
	 * Data sent (as far as we can tell).
	 * If this advertises a larger window than any other segment,
	 * then remember the size of the advertised window.
	 * Any pending ACK has now been sent.
	 */
	if (win > 0 && SEQ_GT(tp->rcv_nxt+win, tp->rcv_adv))
		tp->rcv_adv = tp->rcv_nxt + win;
	tp->last_ack_sent = tp->rcv_nxt;
	tp->t_flags &= ~TF_ACKNOW;
	TCP_CLEAR_DELACK(tp);
#ifdef DIAGNOSTIC
	if (maxburst < 0)
		printf("tcp_output: maxburst exceeded by %d\n", -maxburst);
#endif
	if (sendalot && (!tcp_do_newreno || --maxburst))
		goto again;
	return (0);
}

void
tcp_setpersist(tp)
	register struct tcpcb *tp;
{
	register int t = ((tp->t_srtt >> 2) + tp->t_rttvar) >> (1 + 2);
	int nticks;

	if (TCP_TIMER_ISARMED(tp, TCPT_REXMT))
		panic("tcp_output REXMT");
	/*
	 * Start/restart persistance timer.
	 */
	if (t < tp->t_rttmin)
		t = tp->t_rttmin;
	TCPT_RANGESET(nticks, t * tcp_backoff[tp->t_rxtshift],
	    TCPTV_PERSMIN, TCPTV_PERSMAX);
	TCP_TIMER_ARM(tp, TCPT_PERSIST, nticks);
	if (tp->t_rxtshift < TCP_MAXRXTSHIFT)
		tp->t_rxtshift++;
}
