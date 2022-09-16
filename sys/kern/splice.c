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

#include <sys/cdefs.h>

#include <sys/atomic.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/filio.h>
#include <sys/kauth.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/ktrace.h>
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

#define KBUF_SIZE(bytes_to_transfer) (MIN(bytes_to_transfer, MAXPHYS))

/*
 * Splicev system call.
 */
/* ARGUSED */

int dosplice(int, struct file *, off_t *, int, struct file *, off_t *, size_t,
			 void *, size_t *, register_t *);
int do_spliceread(int, struct file *, void *, size_t, off_t *, int, size_t *);
int do_splicewrite(int, struct file *, const void *, size_t, off_t *, int,
				   size_t *);
int file_offsets(struct file *, off_t *, off_t **);

int
sys_splice(struct lwp *l, const struct sys_splice_args *uap, register_t *retval)
{
	int error, fd_in, fd_out;
	off_t *off_in, *off_out;
	off_t *in_off, *out_off;
	size_t nbytes;
	struct file *fp_in, *fp_out;

	fp_in = fp_out = NULL;

	fd_in = SCARG(uap, fd_in);
	fd_out = SCARG(uap, fd_out);

	off_in = SCARG(uap, off_in);
	off_out = SCARG(uap, off_out);

	nbytes = SCARG(uap, nbytes);

	if (!nbytes)
		return 0;

	error = EBADF;
	if ((fp_in = fd_getfile(fd_in)) == NULL)
		goto out;

	if ((fp_in->f_flag & FREAD) == 0)
		goto done;

	if ((fp_out = fd_getfile(fd_out)) == NULL)
		goto done;

	if ((fp_out->f_flag & FWRITE) == 0)
		goto done;

	in_off = out_off = NULL;

	if (off_in) {
		error = file_offsets(fp_in, off_in, &in_off);
		if (error)
			goto done;
	}

	if (off_out) {
		error = file_offsets(fp_out, off_out, &out_off);
		if (error)
			goto done;
	}

	error = dosplice(fd_in, fp_in, in_off, fd_out, fp_out, out_off, nbytes,
					SCARG(uap, excess_buffer), SCARG(uap, buffer_size), retval);
	if (error)
		goto done;

	if (in_off) {
		error = copyout(in_off, off_in, sizeof(*in_off));
		if (error)
			goto done;
	}

	if (out_off) {
		error = copyout(out_off, off_out, sizeof(*out_off));
		if (error)
			goto done;
	}

done:
	if (fp_in)
		fd_putfile(fd_in);
	if (fp_out)
		fd_putfile(fd_out);
	if (in_off)
		kmem_free(in_off, sizeof(*in_off));
	if (out_off)
		kmem_free(out_off, sizeof(*out_off));

out:
	return error;
}

int
do_spliceread(int fd, struct file *fp, void *buf, size_t nbyte, off_t *offset,
			  int flags, size_t *len)
{
	struct iovec aiov;
	struct uio auio;
	size_t cnt;
	int error;

	aiov.iov_base = (void *)buf;
	aiov.iov_len = nbyte;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = nbyte;
	auio.uio_rw = UIO_READ;
	auio.uio_vmspace = vmspace_kernel();

	/*
	 * Reads return ssize_t because -1 is returned on error.  Therefore
	 * we must restrict the length to SSIZE_MAX to avoid garbage return
	 * values.
	 */
	if (auio.uio_resid > SSIZE_MAX) {
		error = EINVAL;
		goto out;
	}

	cnt = auio.uio_resid;
	error = (*fp->f_ops->fo_read)(fp, offset, &auio, fp->f_cred, flags);
	if (error)
		if (auio.uio_resid != cnt &&
			(error == ERESTART || error == EINTR || error == EWOULDBLOCK))
			error = 0;
	cnt -= auio.uio_resid;
	ktrgenio(fd, UIO_READ, buf, cnt, error);
	*len = cnt;
out:
	return (error);
}

int
do_splicewrite(int fd, struct file *fp, const void *buf, size_t nbyte,
			   off_t *offset, int flags, size_t *len)
{
	struct iovec aiov;
	struct uio auio;
	size_t cnt;
	int error;

	aiov.iov_base = __UNCONST(buf); /* XXXUNCONST kills const */
	aiov.iov_len = nbyte;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = nbyte;
	auio.uio_rw = UIO_WRITE;
	auio.uio_vmspace = vmspace_kernel();

	/*
	 * Writes return ssize_t because -1 is returned on error.  Therefore
	 * we must restrict the length to SSIZE_MAX to avoid garbage return
	 * values.
	 */
	if (auio.uio_resid > SSIZE_MAX) {
		error = EINVAL;
		goto out;
	}

	cnt = auio.uio_resid;
	error = (*fp->f_ops->fo_write)(fp, offset, &auio, fp->f_cred, flags);
	if (error) {
		if (auio.uio_resid != cnt &&
			(error == ERESTART || error == EINTR || error == EWOULDBLOCK))
			error = 0;
		if (error == EPIPE && !(fp->f_flag & FNOSIGPIPE)) {
			mutex_enter(&proc_lock);
			psignal(curproc, SIGPIPE);
			mutex_exit(&proc_lock);
		}
	}
	cnt -= auio.uio_resid;
	ktrgenio(fd, UIO_WRITE, buf, cnt, error);
	*len = cnt;
out:
	return (error);
}

int
file_offsets(struct file *fp, off_t *user_offset, off_t **kernel_offset)
{
	int error = 0;

	/* offset = NULL; done this way due to 'Werror=Unused-but-set-variable' */
	off_t *offset = *kernel_offset;

	if (fp->f_ops->fo_seek == NULL) {
		error = ESPIPE;
		goto out;
	} else {
		offset = kmem_alloc(sizeof(*offset), KM_SLEEP);
		error = copyin(user_offset, offset, sizeof(*offset));
		if (error)
			goto out;

		error = (*fp->f_ops->fo_seek)(fp, *offset, SEEK_SET, offset, 0);
		if (error)
			goto out;
	}

out:
	*kernel_offset = offset;
	return error;
}

int
dosplice(int fd_in, struct file *fp_in, off_t *off_in, int fd_out,
		 struct file *fp_out, off_t *off_out, size_t len, void *excess_buffer,
		 size_t *buffer_size, register_t *retval)
{
	int error, ioctl_ret;
	off_t offset;
	size_t bytes_written, bytes_to_write, write_size, bytes_transferred,
		total_bytes_transferred;
	void *kernel_buffer = NULL, *kbuf_p = NULL;

	error = 0;

	if ((fp_in->f_type == DTYPE_PIPE) && (fp_out->f_type == DTYPE_PIPE))
		if (fp_in->f_pipe == fp_out->f_pipe) {
			error = EINVAL;
			goto done;
		}

	kernel_buffer = kmem_alloc(KBUF_SIZE(len), KM_SLEEP);

	total_bytes_transferred = 0;

	while (total_bytes_transferred < len) {
		offset = off_in ? *off_in : fp_in->f_offset;
		bytes_to_write = bytes_written = ioctl_ret = 0;
		error = do_spliceread(fd_in, fp_in, kernel_buffer, KBUF_SIZE(len),
							  &offset, FOF_UPDATE_OFFSET, &bytes_to_write);
		if (error)
			goto done;

		/* no more data in the recv queue */
		if (bytes_to_write == 0)
			break;

		if (off_in)
			*off_in = offset;
		else
			fp_in->f_offset = offset;

		while (bytes_to_write > 0) {
			bytes_transferred = 0;
			error = (*fp_out->f_ops->fo_ioctl)(fp_out, FIONSPACE, &ioctl_ret);
			if (error)
				goto done;
			else {
				if (ioctl_ret == 0) {
					if (fp_out->f_type == DTYPE_VNODE)
						write_size = bytes_to_write;
					else
						/*
						 * can't go further, until there is space available on
						 * the queue
						 */
						break;
					/* write to the excess_buffer */
				} else
					write_size = MIN(ioctl_ret, bytes_to_write);
			}

write:
			kbuf_p = (void *)((uintptr_t)kernel_buffer +
								total_bytes_transferred);
			offset = off_out ? *off_out : fp_out->f_offset;
			error = do_splicewrite(fd_out, fp_out, kbuf_p, write_size, &offset,
								   FOF_UPDATE_OFFSET, &bytes_written);
			if (error)
				goto done;

			if (off_out)
				*off_out = offset;
			else
				fp_out->f_offset = offset;

			bytes_transferred += bytes_written;
			total_bytes_transferred += bytes_written;

			/* send queue only partially filled */
			if (bytes_written != write_size) {
				write_size -= bytes_written;
				goto write;
			}
			bytes_to_write -= bytes_transferred;
		}

		/* case of short write */
		if (bytes_to_write > 0) {

			/*
			 * once we are in this, we are not going back up to the loop
			 * we can set retval here itself
			 */

			/* write the data already read in */
			error = copyout((void *)((uintptr_t)kernel_buffer +
								total_bytes_transferred), excess_buffer,
							bytes_to_write);
			if (error)
				goto done;
			else {
				error = copyout(&bytes_to_write, buffer_size, sizeof(size_t));
				if (error)
					goto done;
				else
					break;
			}
		}
	}

	/* return unread bytes */
	*retval = len - total_bytes_transferred - bytes_to_write;
	error = 0;

done:
	if (kernel_buffer)
		kmem_free(kernel_buffer, KBUF_SIZE(len));

	return error;
}
