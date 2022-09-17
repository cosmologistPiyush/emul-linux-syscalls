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

#include <sys/cdefs.h>

#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/splice.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/unistd.h>
#include <sys/wait.h>

#include <netdb.h>

#include <atf-c.h>
#include <atf-c/macros.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "h_macros.h"

#define PORT "3490"

static int in_fd, out_fd;

static size_t
preparation(size_t size)
{
	char *buf = NULL;
	int error, fd;
	RL(fd = open("/dev/urandom", O_RDONLY, S_IRUSR));

	RL(in_fd = open("read", O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR));

	REQUIRE_LIBC(buf = malloc(size + 1), NULL);
	buf[size] = '\0';

	error = read(fd, buf, size - 1);
	ATF_REQUIRE_MSG((error > 0), "%s\n", "/dev/urandom not working");

	error = write(in_fd, buf, error);
	ATF_REQUIRE_MSG((error > 0), "%s\n", "read file doesn't have data");

	RL(fsync(in_fd));
	RL(close(in_fd));

	RL(in_fd = open("read", O_RDONLY, S_IRUSR));

	RL(out_fd = open("write", O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR));

	/* return the number of bytes written */
	return (size_t)error;
}

static void
success_check(size_t file_in_size)
{
	struct stat fd_out;

	ATF_REQUIRE_MSG(fsync(out_fd) == 0, "%s\n", "fsync failed");

	RL(fstat(out_fd, &fd_out));

	ATF_CHECK(fd_out.st_size > 0);

	/* fd_out size doesn't contain EOF */
	ATF_REQUIRE_MSG(file_in_size == (size_t)fd_out.st_size, "%s\n",
					"splice unsuccessful");
}

static void
cleanup(void)
{
	close(in_fd);
	close(out_fd);
	unlink("read");
	unlink("write");
}

ATF_TC_WITH_CLEANUP(regularfile_splice_check);

ATF_TC_HEAD(regularfile_splice_check, tc)
{
	atf_tc_set_md_var(tc, "descr",
					  "transferring data from one regular file to another");
}

ATF_TC_BODY(regularfile_splice_check, tc)
{
	int err;
	size_t bytes_to_transfer;

	bytes_to_transfer = preparation(47);
	ATF_REQUIRE(bytes_to_transfer > 0);

	/* regular files */
	RL(err = splice(in_fd, NULL, out_fd, NULL, bytes_to_transfer, 0));

	success_check(bytes_to_transfer);
}

ATF_TC_CLEANUP(regularfile_splice_check, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(regularfile_splice_check2);

ATF_TC_HEAD(regularfile_splice_check2, tc)
{
	atf_tc_set_md_var(tc, "descr",
					  "transferring data from one regular file to another");
}

ATF_TC_BODY(regularfile_splice_check2, tc)
{
	int err;
	off_t off_in, off_out;
	size_t bytes_to_transfer;

	bytes_to_transfer = preparation(47);
	ATF_REQUIRE(bytes_to_transfer > 0);

	off_in = off_out = 0;
	RL(err = splice(in_fd, &off_in, out_fd, &off_out, bytes_to_transfer/2, 0));

	/* making sure file offsets haven't changed */
	ATF_REQUIRE(lseek(in_fd, 0, SEEK_CUR) == 0);
	ATF_REQUIRE(lseek(out_fd, 0, SEEK_CUR) == 0);

	success_check(bytes_to_transfer / 2);

	ATF_CHECK(off_in == off_out);
	ATF_REQUIRE(off_in == (off_t)bytes_to_transfer / 2);

	/* write the rest of the data */
	RL(err = splice(in_fd, &off_in, out_fd, &off_out, bytes_to_transfer/2, 0));

	/* making sure file offsets haven't changed */
	ATF_REQUIRE(lseek(in_fd, 0, SEEK_CUR) == 0);
	ATF_REQUIRE(lseek(out_fd, 0, SEEK_CUR) == 0);

	success_check(bytes_to_transfer);

	ATF_CHECK(off_in == off_out);
	ATF_REQUIRE(off_in == (off_t)bytes_to_transfer);
}

ATF_TC_CLEANUP(regularfile_splice_check2, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(pipe_checks);

ATF_TC_HEAD(pipe_checks, tc)
{
	atf_tc_set_md_var(tc, "descr",
				"write data from a regular file to a pipe and try to read it");
}

ATF_TC_BODY(pipe_checks, tc)
{
	int err, pipe_buf_space, pipefd[2];
	pid_t pid;
	size_t bytes_to_transfer, overflow = 20;

	RL(pipe(pipefd));

	RL(err = ioctl(pipefd[1], FIONSPACE, &pipe_buf_space));

	bytes_to_transfer = preparation(pipe_buf_space + overflow);
	ATF_REQUIRE(bytes_to_transfer > (size_t)pipe_buf_space);

	overflow = bytes_to_transfer - (size_t)pipe_buf_space;
	ATF_REQUIRE(overflow > 0);

	RL(pid = fork());
	if (!pid) {
		RL(close(pipefd[0]));

		RL(err = splice(in_fd, NULL, pipefd[1], NULL, bytes_to_transfer, 0));

		RL(close(pipefd[1]));
	} else {

		RL(close(pipefd[1]));

		RL(err = splice(pipefd[0], NULL, out_fd, NULL, bytes_to_transfer, 0));

		wait(NULL);
		success_check(bytes_to_transfer);

		RL(close(pipefd[0]));
	}
}

ATF_TC_CLEANUP(pipe_checks, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(failing_checks);

ATF_TC_HEAD(failing_checks, tc)
{
	atf_tc_set_md_var(tc, "descr", "making sure the expected errors occur");
}

ATF_TC_BODY(failing_checks, tc)
{
	int fd_invalid, fd_permission, pipefd[2];
	off_t offset;
	size_t bytes_to_transfer;

	bytes_to_transfer = preparation(54);
	ATF_REQUIRE(bytes_to_transfer > 0);

	/* for regular files */
	errno = 0;
	fd_invalid = -1;
	ATF_REQUIRE_ERRNO(EBADF, splice(fd_invalid, NULL, out_fd, NULL,
									bytes_to_transfer, 0));

	ATF_REQUIRE_ERRNO(EBADF, splice(in_fd, NULL, fd_invalid, NULL,
									bytes_to_transfer, 0));

	/* pipes */
	RL(pipe(pipefd));
	offset = 10;

	ATF_REQUIRE_ERRNO(ESPIPE, splice(in_fd, NULL, pipefd[1], &offset,
									 bytes_to_transfer, 0));

	ATF_REQUIRE_ERRNO(ESPIPE, splice(pipefd[0], &offset, out_fd, NULL,
									 bytes_to_transfer, 0));

	ATF_CHECK_ERRNO(EBADF, splice(pipefd[0], NULL, pipefd[0], NULL,
								   bytes_to_transfer, 0));

	fd_permission = open("temp", O_CREAT);

	// ATF_CHECK_ERRNO(EBADF, splice(fd_permission, NULL, out_fd, NULL,
	// 							  bytes_to_transfer, 0));
	ATF_CHECK_ERRNO(EBADF, splice(in_fd, NULL, fd_permission, NULL,
								  bytes_to_transfer, 0));

	RL(close(fd_permission));
	RL(unlink("temp"));
}

ATF_TC_CLEANUP(failing_checks, tc)
{
	cleanup();
}

static int
recv_sock_prep(struct addrinfo *hints)
{
	int err, listener;
	struct addrinfo *res, *res_p;

	/* AI_PASSIVE and hostname = NULL to set ai_add = INADDR_ANY */
	hints->ai_flags = AI_PASSIVE;

	if((err = getaddrinfo(NULL, PORT, hints, &res)) == -1) {
		listener = -1;
		goto out;
	}

	for (res_p = res; (res_p); res_p = res_p->ai_next) {
		listener = socket(res_p->ai_family, res_p->ai_socktype,
						  res_p->ai_protocol);

		if (listener < 0)
			continue;

		// ATF_CHECK(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes,
		// sizeof(int)) == -1);

		if (bind(listener, res_p->ai_addr, res_p->ai_addrlen) == 0)
			break;

		RL(close(listener));
	}

	if(res_p == NULL) {
		listener = -1;
		goto done;
	}

	if (listen(listener, 10) == -1) {
		RL(close(listener));
		listener = -1;
	}

done:
	freeaddrinfo(res);
out:
	return listener;
}

ATF_TC_WITH_CLEANUP(socket_checks);

ATF_TC_HEAD(socket_checks, tc)
{
	atf_tc_set_md_var(tc, "descr", "splice data across socket descriptors");
}

ATF_TC_BODY(socket_checks, tc)
{

	int err, lsockfd, sender, receiver;
	pid_t pid;
	size_t bytes_to_transfer;
	struct addrinfo hints, *res = NULL, *res_p = NULL;
	struct sockaddr_storage sender_addr;
	socklen_t sender_len;

	bytes_to_transfer = preparation(57);
	ATF_REQUIRE(bytes_to_transfer > 0);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	/* No AI_PASSIVE and hostname = NULL to set ai_add = loopback address */
	RL(err = getaddrinfo(NULL, PORT, &hints, &res));
	RL(lsockfd = recv_sock_prep(&hints));

	RL(pid = fork());
	if (!pid) {
		/* child process */

		/* listen() had already been called from the parent.
		 * If the child runs and finishes the parent can take it forward
		 */

		for (res_p = res; res_p != NULL; res_p = res_p->ai_next) {
			if ((sender = socket(res_p->ai_family, res_p->ai_socktype,
								 res_p->ai_protocol)) == -1)
				continue;

			if (connect(sender, res_p->ai_addr, res_p->ai_addrlen) == 0)
				break;

			close(sender);
		}

		if (res_p == NULL) {
			freeaddrinfo(res);
			atf_tc_fail("couldn't connect to the parent\n");
		}


		freeaddrinfo(res);

		/* The child needs to be sender so parent can do verification */
		/* this will never block */

		RL(err = splice(in_fd, NULL, sender, NULL, bytes_to_transfer, 0));

		RL(close(sender));
	} else {

		/* if the parent runs first, it will automatically block on accept(),
		 * forcing the child to run
		 */

		receiver = accept(lsockfd, (struct sockaddr *)&sender_addr, &sender_len);
		if (receiver == -1) {
			close(lsockfd);
			atf_tc_fail("couldn't accept the connection\n");
		}

		RL(err = splice(receiver, NULL, out_fd, NULL, bytes_to_transfer, 0));

		/* make sure the child has sent that data */
		waitpid(-1, NULL, 0);
		RL(close(receiver));
	}

	/* success_check() */
	success_check(bytes_to_transfer);

	RL(close(lsockfd));
}

ATF_TC_CLEANUP(socket_checks, tc)
{
	cleanup();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, regularfile_splice_check);
	ATF_TP_ADD_TC(tp, regularfile_splice_check2);
	ATF_TP_ADD_TC(tp, pipe_checks);
	ATF_TP_ADD_TC(tp, failing_checks);
	ATF_TP_ADD_TC(tp, socket_checks);

	return atf_no_error();
}
