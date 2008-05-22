/* abandon.c */
/* $OpenLDAP: pkg/ldap/libraries/libldap/abandon.c,v 1.41.2.7 2008/02/11 23:26:41 kurt Exp $ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* Portions  Copyright (c) 1990 Regents of the University of Michigan.
 * All rights reserved.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

/*
 * An abandon request looks like this:
 *		AbandonRequest ::= [APPLICATION 16] MessageID
 * and has no response.  (Source: RFC 4511)
 */
#include "lutil.h"

static int
do_abandon(
	LDAP *ld,
	ber_int_t origid,
	ber_int_t msgid,
	LDAPControl **sctrls,
	int sendabandon );

/*
 * ldap_abandon_ext - perform an ldap extended abandon operation.
 *
 * Parameters:
 *	ld			LDAP descriptor
 *	msgid		The message id of the operation to abandon
 *	scntrls		Server Controls
 *	ccntrls		Client Controls
 *
 * ldap_abandon_ext returns a LDAP error code.
 *		(LDAP_SUCCESS if everything went ok)
 *
 * Example:
 *	ldap_abandon_ext( ld, msgid, scntrls, ccntrls );
 */
int
ldap_abandon_ext(
	LDAP *ld,
	int msgid,
	LDAPControl **sctrls,
	LDAPControl **cctrls )
{
	int	rc;

	Debug( LDAP_DEBUG_TRACE, "ldap_abandon_ext %d\n", msgid, 0, 0 );

	/* check client controls */
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_lock( &ld->ld_req_mutex );
#endif

	rc = ldap_int_client_controls( ld, cctrls );
	if ( rc == LDAP_SUCCESS ) {
		rc = do_abandon( ld, msgid, msgid, sctrls, 1 );
	}

#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_unlock( &ld->ld_req_mutex );
#endif

	return rc;
}


/*
 * ldap_abandon - perform an ldap abandon operation. Parameters:
 *
 *	ld		LDAP descriptor
 *	msgid		The message id of the operation to abandon
 *
 * ldap_abandon returns 0 if everything went ok, -1 otherwise.
 *
 * Example:
 *	ldap_abandon( ld, msgid );
 */
int
ldap_abandon( LDAP *ld, int msgid )
{
	Debug( LDAP_DEBUG_TRACE, "ldap_abandon %d\n", msgid, 0, 0 );
	return ldap_abandon_ext( ld, msgid, NULL, NULL ) == LDAP_SUCCESS
		? 0 : -1;
}


int
ldap_pvt_discard(
	LDAP *ld,
	ber_int_t msgid )
{
	int	rc;

#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_lock( &ld->ld_req_mutex );
#endif

	rc = do_abandon( ld, msgid, msgid, NULL, 0 );

#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_unlock( &ld->ld_req_mutex );
#endif

	return rc;
}

static int
do_abandon(
	LDAP *ld,
	ber_int_t origid,
	ber_int_t msgid,
	LDAPControl **sctrls,
	int sendabandon )
{
	BerElement	*ber;
	int		i, err;
	Sockbuf		*sb;
	LDAPRequest	*lr;

	Debug( LDAP_DEBUG_TRACE, "do_abandon origid %d, msgid %d\n",
		origid, msgid, 0 );

	/* find the request that we are abandoning */
start_again:;
	lr = ld->ld_requests;
	while ( lr != NULL ) {
		/* this message */
		if ( lr->lr_msgid == msgid ) {
			break;
		}

		/* child: abandon it */
		if ( lr->lr_origid == msgid && !lr->lr_abandoned ) {
			(void)do_abandon( ld, lr->lr_origid, lr->lr_msgid,
				sctrls, sendabandon );

			/* restart, as lr may now be dangling... */
			goto start_again;
		}

		lr = lr->lr_next;
	}

	if ( lr != NULL ) {
		if ( origid == msgid && lr->lr_parent != NULL ) {
			/* don't let caller abandon child requests! */
			ld->ld_errno = LDAP_PARAM_ERROR;
			return( LDAP_PARAM_ERROR );
		}
		if ( lr->lr_status != LDAP_REQST_INPROGRESS ) {
			/* no need to send abandon message */
			sendabandon = 0;
		}
	}

	/* ldap_msgdelete locks the res_mutex. Give up the req_mutex
	 * while we're in there.
	 */
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_unlock( &ld->ld_req_mutex );
#endif
	err = ldap_msgdelete( ld, msgid );
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_lock( &ld->ld_req_mutex );
#endif
	if ( err == 0 ) {
		ld->ld_errno = LDAP_SUCCESS;
		return LDAP_SUCCESS;
	}

	/* fetch again the request that we are abandoning */
	if ( lr != NULL ) {
		for ( lr = ld->ld_requests; lr != NULL; lr = lr->lr_next ) {
			/* this message */
			if ( lr->lr_msgid == msgid ) {
				break;
			}
		}
	}

	err = 0;
	if ( sendabandon ) {
		if ( ber_sockbuf_ctrl( ld->ld_sb, LBER_SB_OPT_GET_FD, NULL ) == -1 ) {
			/* not connected */
			err = -1;
			ld->ld_errno = LDAP_SERVER_DOWN;

		} else if ( ( ber = ldap_alloc_ber_with_options( ld ) ) == NULL ) {
			/* BER element allocation failed */
			err = -1;
			ld->ld_errno = LDAP_NO_MEMORY;

		} else {
			/*
			 * We already have the mutex in LDAP_R_COMPILE, so
			 * don't try to get it again.
			 *		LDAP_NEXT_MSGID(ld, i);
			 */

			i = ++(ld)->ld_msgid;
#ifdef LDAP_CONNECTIONLESS
			if ( LDAP_IS_UDP(ld) ) {
				struct sockaddr sa = {0};
				/* dummy, filled with ldo_peer in request.c */
				err = ber_write( ber, &sa, sizeof(sa), 0 );
			}
			if ( LDAP_IS_UDP(ld) && ld->ld_options.ldo_version ==
				LDAP_VERSION2 )
			{
				char *dn = ld->ld_options.ldo_cldapdn;
				if (!dn) dn = "";
				err = ber_printf( ber, "{isti",  /* '}' */
					i, dn,
					LDAP_REQ_ABANDON, msgid );
			} else
#endif
			{
				/* create a message to send */
				err = ber_printf( ber, "{iti",  /* '}' */
					i,
					LDAP_REQ_ABANDON, msgid );
			}

			if ( err == -1 ) {
				/* encoding error */
				ld->ld_errno = LDAP_ENCODING_ERROR;

			} else {
				/* Put Server Controls */
				if ( ldap_int_put_controls( ld, sctrls, ber )
					!= LDAP_SUCCESS )
				{
					err = -1;

				} else {
					/* close '{' */
					err = ber_printf( ber, /*{*/ "N}" );

					if ( err == -1 ) {
						/* encoding error */
						ld->ld_errno = LDAP_ENCODING_ERROR;
					}
				}
			}

			if ( err == -1 ) {
				ber_free( ber, 1 );

			} else {
				/* send the message */
				if ( lr != NULL ) {
					assert( lr->lr_conn != NULL );
					sb = lr->lr_conn->lconn_sb;
				} else {
					sb = ld->ld_sb;
				}

				if ( ber_flush2( sb, ber, LBER_FLUSH_FREE_ALWAYS ) != 0 ) {
					ld->ld_errno = LDAP_SERVER_DOWN;
					err = -1;
				} else {
					err = 0;
				}
			}
		}
	}

	if ( lr != NULL ) {
		if ( sendabandon || lr->lr_status == LDAP_REQST_WRITING ) {
			ldap_free_connection( ld, lr->lr_conn, 0, 1 );
		}

		if ( origid == msgid ) {
			ldap_free_request( ld, lr );

		} else {
			lr->lr_abandoned = 1;
		}
	}

#ifdef LDAP_R_COMPILE
	/* ld_abandoned is actually protected by the ld_res_mutex;
	 * give up the ld_req_mutex and get the other */
	ldap_pvt_thread_mutex_unlock( &ld->ld_req_mutex );
	ldap_pvt_thread_mutex_lock( &ld->ld_res_mutex );
#endif

	/* use bisection */
	i = 0;
	if ( ld->ld_nabandoned == 0 ||
		ldap_int_bisect_find( ld->ld_abandoned, ld->ld_nabandoned, msgid, &i ) == 0 )
	{
		ldap_int_bisect_insert( &ld->ld_abandoned, &ld->ld_nabandoned, msgid, i );
	}

	if ( err != -1 ) {
		ld->ld_errno = LDAP_SUCCESS;
	}

#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_unlock( &ld->ld_res_mutex );
	ldap_pvt_thread_mutex_lock( &ld->ld_req_mutex );
#endif
	return( ld->ld_errno );
}

/*
 * ldap_int_bisect_find
 *
 * args:
 *	v:	array of length n (in)
 *	n:	length of array v (in)
 *	id:	value to look for (in)
 *	idxp:	pointer to location of value/insert point
 *
 * return:
 *	0:	not found
 *	1:	found
 *	-1:	error
 */
int
ldap_int_bisect_find( ber_int_t *v, ber_len_t n, ber_int_t id, int *idxp )
{
	int		begin,
			end,
			rc = 0;

	assert( n >= 0 );
	assert( id >= 0 );

	begin = 0;
	end = n - 1;

		if ( n <= 0 || id < v[ begin ] ) {
			*idxp = 0;

		} else if ( id > v[ end ] ) {
			*idxp = n;

		} else {
			int		pos;
			ber_int_t	curid;
	
			do {
				pos = (begin + end)/2;
				curid = v[ pos ];
	
				if ( id < curid ) {
					end = pos - 1;
	
				} else if ( id > curid ) {
					begin = ++pos;
	
				} else {
					/* already abandoned? */
					rc = 1;
					break;
				}
			} while ( end >= begin );
	
			*idxp = pos;
		}

	return rc;
}

/*
 * ldap_int_bisect_insert
 *
 * args:
 *	vp:	pointer to array of length *np (in/out)
 *	np:	pointer to length of array *vp (in/out)
 *	id:	value to insert (in)
 *	idx:	location of insert point (as computed by ldap_int_bisect_find())
 *
 * return:
 *	0:	inserted
 *	-1:	error
 */
int
ldap_int_bisect_insert( ber_int_t **vp, ber_len_t *np, int id, int idx )
{
	ber_int_t	*v;
	ber_len_t	n;
	int		i;

	assert( vp != NULL );
	assert( np != NULL );
	assert( *np >= 0 );
	assert( idx >= 0 );
	assert( idx <= *np );

	n = *np;

	v = ber_memrealloc( *vp, sizeof( ber_int_t ) * ( n + 1 ) );
	if ( v == NULL ) {
		return -1;
	}
	*vp = v;

	for ( i = n; i > idx; i-- ) {
		v[ i ] = v[ i - 1 ];
	}
	v[ idx ] = id;
	++(*np);

	return 0;
}

/*
 * ldap_int_bisect_delete
 *
 * args:
 *	vp:	pointer to array of length *np (in/out)
 *	np:	pointer to length of array *vp (in/out)
 *	id:	value to delete (in)
 *	idx:	location of value to delete (as computed by ldap_int_bisect_find())
 *
 * return:
 *	0:	deleted
 */
int
ldap_int_bisect_delete( ber_int_t **vp, ber_len_t *np, int id, int idx )
{
	ber_int_t	*v;
	ber_len_t	n;
	int		i;

	assert( vp != NULL );
	assert( np != NULL );
	assert( *np >= 0 );
	assert( idx >= 0 );
	assert( idx < *np );

	v = *vp;

	assert( v[ idx ] == id );

	--(*np);
	n = *np;

	for ( i = idx; i < n; i++ ) {
		v[ i ] = v[ i + 1 ];
	}

	return 0;
}

