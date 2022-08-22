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

#include <sys/atomic.h>
#include <sys/cdefs.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/filio.h>
#include <sys/kauth.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/splicev.h>
#include <sys/stat.h>
#include <sys/stdint.h>
#include <sys/syscallargs.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/vnode.h>

#define IOV_LEN 1024

/*
 * Splicev system call.
 */
/* ARGUSED */
int sys_splicev(struct lwp *l, const struct sys_splicev_args *uap,
                register_t *retval) {
	struct file *fp_in, *fp_out;
	int *bytes_to_read, error, fd_in, fd_out, iovlen;
	register_t *int_retval;
	size_t bytes_rem_to_read, bytes_rem_to_write, bytes_written, cnt,
		   nbytes, total_bytes_transfered;
	struct iovec aiov;
	off_t off_in, off_out;
	//struct uio auio;
	struct spliceops *ops = NULL, *ops_p;
	struct splice_args *spargs = NULL;
	struct sendfile_args *sfargs = NULL;
	uintptr_t iov_buf;

	nbytes = SCARG(uap, len);
	if (!nbytes) {
		error = 0;
		goto out;
	} else if (nbytes > SSIZE_MAX) {
		error = EINVAL;
		goto out;
	}

	fd_in = SCARG(uap, fd_in);
	fd_out = SCARG(uap, fd_out);

	if ((fp_in = fd_getfile(fd_in)) == NULL) {
		error = EBADF;
		goto out;
	}

	if ((fp_in->f_flag & FREAD) == 0) {
		error = EBADF;
		goto done;
	}
	if ((fp_out = fd_getfile(fd_out)) == NULL) {
		error = EBADF;
		goto out;
	}

	if ((fp_out->f_flag & FWRITE) == 0) {
		error = EBADF;
		goto done;
	}

	// iovcnt = 1;

	off_in = SCARG(uap, offset);
	ops_p = SCARG(uap, ops);

	if (ops_p != NULL) {
		ops = kmem_alloc(sizeof(*ops), KM_SLEEP);
		error = copyin(ops_p, ops, sizeof(*ops));
		if (error)
			goto done;
		switch(ops->choice) {
			case SPLICE:
				spargs = kmem_alloc(sizeof(*spargs), KM_SLEEP);
				error = copyin(ops_p->spliceargs, spargs, sizeof(*spargs));
				if (error)
					goto done;
				ops->spliceargs = spargs;
				off_out = spargs->off_out;
				/*TODO: figure out flags; */
				break;
			case SENDFILE:
				sfargs = kmem_alloc(sizeof(*sfargs), KM_SLEEP);
				error = copyin(ops_p->sendfileargs, sfargs, sizeof(*sfargs));
				if (error)
					goto done;
				ops->sendfileargs = sfargs;
				/*TODO: play with aiov and fit in headers and trailers; */
				/*NOTE: use sbytes for retval later; */
				/*TODO: figure out flags; */
				break;
		}
	}


	iovlen = nbytes;
	aiov.iov_base = kmem_alloc(iovlen, KM_SLEEP);
	aiov.iov_len = nbytes;

	bytes_to_read = NULL;
	int_retval = NULL;
	total_bytes_transfered = 0;

	while (total_bytes_transfered < nbytes) {

		/*
		 * estimate the amount of space available on the send queue of fd_out
		 * for now, dont read more than the write space.
		 * NOTE: Is there any point of reading all the data in struct iovec,
		 *		 sort of like buffering all the read and then writing as much
		 *		 as the send queue allows?
		 */
		error = (*fp_out->f_ops->fo_ioctl)(fp_out, FIONSPACE, bytes_to_read);
		if (error == -1) {
			error = ENOTTY;
			goto done;
		} else {
			if (*bytes_to_read == 0) {
				if (fp_out->f_type == DTYPE_VNODE)
					*bytes_to_read = nbytes;
				/*FIX: can we have more cases? check overflow in sockets */
			}
		}

		/* Limit the size of read data to SSIZE_MAX
		 * NOTE: Is there any point in limiting *bytes_to_read to SSIZE_MAX?
		 */
		
		bytes_rem_to_read = * (size_t *)bytes_to_read;

		/*
		 * start reading and writing contents
		 * adjust the flags variable
		 */
		bytes_written = 0;
		while (bytes_rem_to_read > 0) {
			iov_buf = (uintptr_t) aiov.iov_base;

			/* read as much as you can <= the space available on send queue */
			error = dofileread(fd_in, fp_in, (void *)iov_buf,
					bytes_rem_to_read, &off_in, FOF_UPDATE_OFFSET, int_retval);
			if (!error)
				goto done;

			//iov_buf = aiov.iov_base;
			bytes_rem_to_write = *int_retval;

			cnt = 0;
write:
			/* make sure all bytes read in aiov.iov_base, are written */
			error = dofilewrite(fd_out, fp_out, (void *)iov_buf,
					bytes_rem_to_write, &off_out, FOF_UPDATE_OFFSET, int_retval);
			
			if (!error)
				goto done;
			else {
				bytes_written = *int_retval;
				cnt += bytes_written;
				if (bytes_written != bytes_rem_to_write) {
					/* finish the write of buffered data */
					bytes_rem_to_write -= bytes_written;
					iov_buf = (uintptr_t)aiov.iov_base;
					iov_buf += bytes_written;
					goto write;
				}
			}

			aiov.iov_base = NULL;
			bytes_rem_to_read -= cnt;

			total_bytes_transfered += cnt;
		}
	}


done:
	if (fp_in)
		fd_putfile(fd_in);

	if (fp_out)
		fd_putfile(fd_out);

	if (ops) {
		switch(ops->choice) {
			case SPLICE:
				kmem_free(spargs, sizeof(*spargs));
				break;
			case SENDFILE:
				kmem_free(sfargs, sizeof(*sfargs));
		}
		kmem_free(ops, sizeof(*ops));
	}

out:
	return error;
}
