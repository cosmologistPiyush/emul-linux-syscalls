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
#include <sys/pax.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/syscallargs.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/vnode.h>

#define KBUF_SIZE(bytes_to_transfer)	(MIN(bytes_to_transfer, MAXPHYS))

/*
 * Splicev system call.
 */
/* ARGUSED */
int
sys_splice(struct lwp *l, const struct sys_splice_args *uap, register_t *retval)
{
	struct file *fp_in, *fp_out;
	int error, fd_in, fd_out;
	register_t *int_retval = NULL;
	size_t bytes_rem_to_transfer, bytes_written, bytes_rem_to_write, *excess_buf_size, len;
	void *excess_buf, *kernel_buffer;

	fd_in = SCARG(uap, fd_in);
	fd_out = SCARG(uap, fd_out);

	error = EBADF;
	if ((fp_in = fd_getfile(fd_in)) == NULL)
		goto out;

	if ((fp_in->f_flag & FREAD) == 0)
		goto done;

	if ((fp_out = fd_getfile(fd_out)) == NULL)
		goto done;

	if ((fp_out->f_flag & FWRITE) == 0)
		goto done;

	error = 0;

	len = SCARG(uap, nbytes);
	excess_buf= SCARG(uap, excess_buffer);
	excess_buf_size = SCARG(uap, buffer_size);

	kernel_buffer = kmem_alloc(KBUF_SIZE(len), KM_SLEEP);

	excess_buf = kernel_buffer = NULL;

	bytes_rem_to_transfer = len;

	while (bytes_rem_to_transfer > 0) {
		bytes_rem_to_write = bytes_written = 0;
		error = dofileread(fd_in, fp_in, kernel_buffer, KBUF_SIZE(len),
				&fp_in->f_offset, FOF_UPDATE_OFFSET, int_retval);
		if (!error)
			goto done;

		bytes_rem_to_write = * (size_t *)int_retval;

		error = dofilewrite(fd_out, fp_out, kernel_buffer, bytes_rem_to_write,
				&fp_out->f_offset, FOF_UPDATE_OFFSET, int_retval);

		if (!error)
			goto done;

		bytes_written = * (size_t *)int_retval;
		bytes_rem_to_transfer -= bytes_written;

		/* case of short write */
		if (bytes_rem_to_write != bytes_written) {

			/*
			 * once we are in this, we are not going back up to the loop
			 * we can set retval here itself
			 */

			/* size of the excess buffer */
			bytes_rem_to_write -= bytes_written;

			*retval = bytes_rem_to_transfer - bytes_rem_to_write;
			
			/* write the data already read in */
			error = copyout((void *)((uintptr_t)kernel_buffer + bytes_written), excess_buf,
					bytes_rem_to_write);
			if (!error)
				goto done;
			else {
				error = copyout(&bytes_rem_to_write, excess_buf_size, sizeof(size_t));
				goto done;
			}
		}	
	}

	/* return unread bytes */
	*retval = 0;

	
done:
	if (fp_in)
		fd_putfile(fd_in);
	if (fp_out)
		fd_putfile(fd_out);
	if (kernel_buffer)
		kmem_free(kernel_buffer, KBUF_SIZE(len));

out:
	return error;
}
