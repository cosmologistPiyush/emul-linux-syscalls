/* $NetBSD: fdset.h,v 1.1.1.2 2003/06/01 14:01:33 atatat Exp $ */
/*
 * Copyright (c) 2001, 2002 Sendmail, Inc. and its suppliers.
 *      All rights reserved.
 *
 * By using this file, you agree to the terms and conditions set
 * forth in the LICENSE file which can be found at the top level of
 * the sendmail distribution.
 *
 *	Id: fdset.h,v 1.3.10.2 2002/12/10 04:02:25 ca Exp
 */

#ifndef	SM_FDSET_H
# define SM_FDSET_H

/*
**  Note: SM_FD_OK_SELECT(fd) requires that ValidSocket(fd) has been checked
**	before.
*/

#  define SM_FD_SET(fd, pfdset)		FD_SET(fd, pfdset)
#  define SM_FD_ISSET(fd, pfdset)	FD_ISSET(fd, pfdset)
#  define SM_FD_SETSIZE			FD_SETSIZE
#  define SM_FD_OK_SELECT(fd)		(FD_SETSIZE <= 0 || (fd) < FD_SETSIZE)

#endif /* SM_FDSET_H */
