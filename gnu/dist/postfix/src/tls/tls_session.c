/*	$NetBSD: tls_session.c,v 1.1.1.1 2005/08/18 21:11:10 rpaulo Exp $	*/

/*++
/* NAME
/*	tls_session
/* SUMMARY
/*	TLS client and server session routines
/* SYNOPSIS
/*	#include <tls.h>
/*
/*	int	tls_session_stop(ctx, stream, timeout, failure, tls_info)
/*	SSL_CTX	*ctx;
/*	VSTREAM	*stream;
/*	int	timeout;
/*	int	failure;
/*	tls_info_t *tls_info;
/*
/*	VSTRING	*tls_session_passivate(session)
/*	SSL_SESSION *session;
/*
/*	SSL_SESSION *tls_session_activate(session_data, session_data_len)
/*	char	*session_data;
/*	int	session_data_len;
/* DESCRIPTION
/*	tls_session_stop() implements the tls_server_shutdown()
/*	and the tls_client_shutdown() routines.
/*
/*	tls_session_passivate() converts an SSL_SESSION object to
/*	VSTRING. The result is a null pointer in case of problems,
/*	otherwise it should be disposed of with vstring_free().
/*
/*	tls_session_activate() reanimates a passivated SSL_SESSION object.
/*	The result is a null pointer in case of problems,
/*	otherwise it should be disposed of with SSL_SESSION_free().
/* LICENSE
/* .ad
/* .fi
/*	This software is free. You can do with it whatever you want.
/*	The original author kindly requests that you acknowledge
/*	the use of his software.
/* AUTHOR(S)
/*	Originally written by:
/*	Lutz Jaenicke
/*	BTU Cottbus
/*	Allgemeine Elektrotechnik
/*	Universitaetsplatz 3-4
/*	D-03044 Cottbus, Germany
/*
/*	Updated by:
/*	Wietse Venema
/*	IBM T.J. Watson Research
/*	P.O. Box 704
/*	Yorktown Heights, NY 10598, USA
/*--*/

/* System library. */

#include <sys_defs.h>

#ifdef USE_TLS

/* Utility library. */

#include <vstream.h>
#include <msg.h>
#include <mymalloc.h>

/* TLS library. */

#define TLS_INTERNAL
#include <tls.h>

/* Application-specific. */

#define STR	vstring_str

/* tls_session_stop - shut down the TLS connection and reset state */

void    tls_session_stop(SSL_CTX *ctx, VSTREAM *stream, int timeout,
			         int failure, tls_info_t *tls_info)
{
    const char *myname = "tls_session_stop";
    TLScontext_t *TLScontext;
    int     retval;

    /*
     * Sanity check.
     */
    TLScontext = (TLScontext_t *) vstream_context(stream);
    if (TLScontext == 0)
	msg_panic("%s: stream has no active TLS context", myname);

    /*
     * Perform SSL_shutdown() twice, as the first attempt will send out the
     * shutdown alert but it will not wait for the peer's shutdown alert.
     * Therefore, when we are the first party to send the alert, we must call
     * SSL_shutdown() again. On failure we don't want to resume the session,
     * so we will not perform SSL_shutdown() and the session will be removed
     * as being bad.
     */
    if (!failure) {
	retval = tls_bio_shutdown(vstream_fileno(stream), timeout, TLScontext);
	if (retval == 0)
	    tls_bio_shutdown(vstream_fileno(stream), timeout, TLScontext);
    }

    /*
     * Free the SSL structure and the BIOs. Warning: the internal_bio is
     * connected to the SSL structure and is automatically freed with it. Do
     * not free it again (core dump)!! Only free the network_bio.
     * 
     * XXX SSL_CTX_flush_sessions() searches memory for expired sessions and
     * removes them from memory and external cache.
     */
    SSL_free(TLScontext->con);

    BIO_free(TLScontext->network_bio);
    FREE_TLS_CONTEXT(TLScontext);
    tls_stream_stop(stream);
    SSL_CTX_flush_sessions(ctx, time(NULL));

    *tls_info = tls_info_zero;
}

/* tls_session_passivate - passivate SSL_SESSION object */

VSTRING *tls_session_passivate(SSL_SESSION *session)
{
    const char *myname = "tls_session_passivate";
    int     estimate;
    int     actual_size;
    VSTRING *session_data;
    unsigned char *ptr;

    /*
     * First, find out how much memory is needed for the passivated
     * SSL_SESSION object.
     */
    estimate = i2d_SSL_SESSION(session, (unsigned char **) 0);
    if (estimate <= 0) {
	msg_warn("%s: i2d_SSL_SESSION failed: unable to cache session", myname);
	return (0);
    }

    /*
     * Passivate the SSL_SESSION object. The use of a VSTRING is slightly
     * wasteful but is convenient to combine data and length.
     */
    session_data = vstring_alloc(estimate);
    ptr = (unsigned char *) STR(session_data);
    actual_size = i2d_SSL_SESSION(session, &ptr);
    if (actual_size != estimate) {
	msg_warn("%s: i2d_SSL_SESSION failed: unable to cache session", myname);
	vstring_free(session_data);
	return (0);
    }
    VSTRING_AT_OFFSET(session_data, actual_size);	/* XXX not public */

    return (session_data);
}

/* tls_session_activate - activate passivated session */

SSL_SESSION *tls_session_activate(char *session_data, int session_data_len)
{
    SSL_SESSION *session;
    unsigned char *ptr;

    /*
     * Activate the SSL_SESSION object.
     */
    ptr = (unsigned char *) session_data;
    session = d2i_SSL_SESSION((SSL_SESSION **) 0, &ptr, session_data_len);
    if (!session)
	tls_print_errors();

    return (session);
}

#endif
