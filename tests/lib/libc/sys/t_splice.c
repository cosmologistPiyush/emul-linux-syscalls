/* $NetBSD: t_splice.c,v V DATE TIME NAME Exp $ */

/*-
 * Copyright (c) 2001, 2008 The NetBSD Foundation, Inc.
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

#include <atf-c/macros.h>
#include <stdlib.h>
#include <sys/cdefs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/splice.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/unistd.h>
#include <unistd.h>
#include <paths.h>

#include "h_macros.h"

/* TODO: get avail space on pipefd[1] with fionspace. write as much avail then
 * write extra, test the output
 */

static int in_fd, out_fd;

static size_t
preparation(size_t size)
{
	char *buf = NULL;
	int error, fd;
	fd = open("/dev/urandom", O_RDONLY, S_IRUSR);
	ATF_REQUIRE_MSG(fd >= 0, "%s\n", "file to read has not been created");

	in_fd = open("read", O_CREAT|O_TRUNC|O_RDWR, S_IRUSR|S_IWUSR);
	ATF_REQUIRE_MSG(in_fd >= 0, "%s\n", "file to read has not been created");

	buf = malloc(size+1);
	ATF_REQUIRE(buf != NULL);
	buf[size] = '\0';

	error = read(fd, buf, size-1);
	ATF_REQUIRE_MSG((error > 0), "%s\n", "/dev/urandom not working");

	error = write(in_fd, buf, error);
	ATF_REQUIRE_MSG((error > 0), "%s\n", "read file doesn't have data");

	ATF_REQUIRE(fsync(in_fd) == 0);
	ATF_REQUIRE(close(in_fd) == 0);

	in_fd = open("read", O_RDONLY, S_IRUSR);
	ATF_REQUIRE_MSG(fd > 0, "%s\n", "file to read from doesn't exist");

	out_fd = open("write", O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR);
	ATF_REQUIRE(fd > 0);

	/* return the number of bytes written */
	return (size_t)error;
}

static void
success_check(size_t file_in_size, size_t excess_size, size_t bytes_unread)
{
	struct stat fd_out;

	ATF_REQUIRE_MSG(fsync(out_fd) == 0, "%s\n", "fsync failed");

	ATF_REQUIRE(fstat(out_fd, &fd_out) == 0);

	/* fd_out size doesn't contain EOF yet, as its still open */
	ATF_REQUIRE_MSG((file_in_size - (size_t)fd_out.st_size) == (excess_size +
				bytes_unread), "%s\n", "error in syscall implementation");
}

ATF_TC_WITH_CLEANUP(simple_splice_check);

ATF_TC_HEAD(simple_splice_check, tc)
{
	atf_tc_set_md_var(tc, "descr", "transferring data from one regular file to another");
}

ATF_TC_BODY(simple_splice_check, tc)
{
	char *excess_buffer = NULL;
	int err;
	size_t bytes_to_transfer, bytes_unread, excess_size = 0; 

	bytes_to_transfer = preparation(47);
	ATF_REQUIRE(bytes_to_transfer > 0);

	REQUIRE_LIBC(excess_buffer = calloc(bytes_to_transfer, sizeof(char)), NULL);

	/* regular files */
	err = splice(in_fd, out_fd, bytes_to_transfer, excess_buffer, &excess_size);
	ATF_CHECK_MSG(err >= 0, "%s\n%i:%s\n", "splice failed", err, strerror(err));

	/* return the number of bytes unread */
	bytes_unread = (size_t)err;

	success_check(bytes_to_transfer, excess_size, bytes_unread);
	
	while ((excess_size != 0) && ((err = write (out_fd, excess_buffer,
									excess_size)) != 0)) {
		if (err == -1) {
			if (errno == EINTR)
				continue;
			perror("write");
			break;
		}
		excess_size -= err;
		excess_buffer += err;
	}

	free(excess_buffer);
}

ATF_TC_CLEANUP(simple_splice_check, tc)
{
	if(close(in_fd) != 0)
		printf("close\n");
	if(close(out_fd) != 0)
		printf("close\n");
	unlink("read");
	unlink("write");
}

ATF_TC_WITH_CLEANUP(pipe_checks);

ATF_TC_HEAD(pipe_checks, tc)
{
	atf_tc_set_md_var(tc, "descr", "write data from a regular file to a pipe and try to read it");
}

ATF_TC_BODY(pipe_checks, tc)
{
	char *excess_buffer = NULL, *retbuf = NULL;
	int err, pipefd[2];
	size_t bytes_to_transfer, bytes_unread, excess_size = 0;

	ATF_REQUIRE(pipe(pipefd) == 0);

	bytes_to_transfer = preparation(47);
	ATF_REQUIRE(bytes_to_transfer > 0);

	/* allocated with calloc() to initialise the characters with '\0' */
	REQUIRE_LIBC(excess_buffer = calloc(bytes_to_transfer, sizeof(char)), NULL);
	REQUIRE_LIBC(retbuf = calloc(bytes_to_transfer, sizeof(char)), NULL);

	//extra_bytes_to_transfer -= pipe_buf_space; 

	err = splice(in_fd, pipefd[1], bytes_to_transfer, excess_buffer, &excess_size);
	ATF_CHECK_MSG(err >= 0, "%s\n%i:%s\n", "splice failed", err, strerror(err));

	/* return the number of bytes unread */
	bytes_unread = (size_t)err;

	ATF_CHECK(excess_size == 0);
	if (excess_size > 0) {
		strncpy(retbuf, excess_buffer, excess_size);
		memset(excess_buffer, '\0', excess_size);
	}

	ATF_REQUIRE(close(pipefd[1]) == 0);

	err = splice(pipefd[0], out_fd, bytes_to_transfer, excess_buffer, &excess_size);
	ATF_CHECK_MSG(err >= 0, "%s\n%i:%s\n", "splice failed", err, strerror(err));

	success_check(bytes_to_transfer, (strlen(retbuf) + excess_size), bytes_unread);

	ATF_REQUIRE(close(pipefd[0]) == 0);
	free(excess_buffer);
	free(retbuf);
}

ATF_TC_CLEANUP(pipe_checks, tc)
{
	if(close(in_fd) != 0)
		printf("close\n");
	if(close(out_fd) != 0)
		printf("close\n");
	unlink("read");
	unlink("write");
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, simple_splice_check);
	ATF_TP_ADD_TC(tp, pipe_checks);

	return atf_no_error();
}
