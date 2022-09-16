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
	fd = open("/dev/urandom", O_RDONLY, S_IRUSR);
	ATF_REQUIRE_MSG(fd > 0, "%s\n", "/dev/urandom issue");

	in_fd = open("read", O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
	ATF_REQUIRE_MSG(in_fd > 0, "%s\n", "file to read has not been created");

	buf = malloc(size + 1);
	ATF_REQUIRE(buf != NULL);
	buf[size] = '\0';

	error = read(fd, buf, size - 1);
	ATF_REQUIRE_MSG((error > 0), "%s\n", "/dev/urandom not working");

	error = write(in_fd, buf, error);
	ATF_REQUIRE_MSG((error > 0), "%s\n", "read file doesn't have data");

	ATF_REQUIRE(fsync(in_fd) == 0);
	ATF_REQUIRE(close(in_fd) == 0);

	in_fd = open("read", O_RDONLY, S_IRUSR);
	ATF_REQUIRE_MSG(in_fd > 0, "%s\n", "file to read from doesn't exist");

	out_fd = open("write", O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);
	ATF_REQUIRE(out_fd > 0);

	/* return the number of bytes written */
	return (size_t)error;
}

static void
success_check(size_t file_in_size, size_t excess_size, size_t bytes_unread)
{
	struct stat fd_out;

	ATF_REQUIRE_MSG(fsync(out_fd) == 0, "%s\n", "fsync failed");

	ATF_REQUIRE(fstat(out_fd, &fd_out) == 0);

	ATF_CHECK(fd_out.st_size > 0);

	/* fd_out size doesn't contain EOF */
	ATF_REQUIRE_MSG((file_in_size - (size_t)fd_out.st_size) ==
						(excess_size + bytes_unread),
					"%s\n", "unsuccess: error in syscall implementation");
}

static void
write_out_excess(char *buf, size_t len, ...)
{
	int err;
	off_t *offset = NULL;
	va_list ap;

	va_start(ap, len);
	offset = va_arg(ap, off_t *);

	if (!offset) {
		while ((len != 0) && ((err = write(out_fd, buf, len)) != 0)) {
			if (err == -1) {
				if (errno == EINTR)
					continue;
				perror("write");
				break;
			}
			len -= err;
			buf += err;
		}
	} else {
		while ((len != 0) && ((err = pwrite(out_fd, buf, len, *offset)) != 0)) {
			if (err == -1) {
				if (errno == EINTR)
					continue;
				perror("write");
				break;
			}
			len -= err;
			buf += err;
			*offset += err;
		}
	}

	va_end(ap);

	ATF_CHECK(len == 0);
}

ATF_TC_WITH_CLEANUP(regularfile_splice_check);

ATF_TC_HEAD(regularfile_splice_check, tc)
{
	atf_tc_set_md_var(tc, "descr",
					  "transferring data from one regular file to another");
}

ATF_TC_BODY(regularfile_splice_check, tc)
{
	char *excess_buffer = NULL;
	int err;
	size_t bytes_to_transfer, bytes_unread, excess_size = 0;

	bytes_to_transfer = preparation(47);
	ATF_REQUIRE(bytes_to_transfer > 0);

	REQUIRE_LIBC(excess_buffer = calloc(bytes_to_transfer, sizeof(char)), NULL);

	/* regular files */
	err = splice(in_fd, NULL, out_fd, NULL, bytes_to_transfer, excess_buffer,
				 &excess_size);
	ATF_CHECK_MSG(err >= 0, "%s\n%i:%s\n", "splice failed", err,
				  strerror(errno));

	/* return the number of bytes unread */
	bytes_unread = (size_t)err;

	success_check(bytes_to_transfer, excess_size, bytes_unread);
	write_out_excess(excess_buffer, excess_size, NULL);
	success_check(bytes_to_transfer, 0, bytes_unread);
	free(excess_buffer);
}

ATF_TC_CLEANUP(regularfile_splice_check, tc)
{
	if (close(in_fd) != 0)
		printf("close\n");
	if (close(out_fd) != 0)
		printf("close\n");
	unlink("read");
	unlink("write");
}

ATF_TC_WITH_CLEANUP(regularfile_splice_check2);

ATF_TC_HEAD(regularfile_splice_check2, tc)
{
	atf_tc_set_md_var(tc, "descr",
					  "transferring data from one regular file to another");
}

ATF_TC_BODY(regularfile_splice_check2, tc)
{
	char *excess_buffer = NULL;
	int err;
	off_t off_in, off_out;
	size_t bytes_to_transfer, bytes_unread, excess_size = 0;

	bytes_to_transfer = preparation(47);
	ATF_REQUIRE(bytes_to_transfer > 0);

	REQUIRE_LIBC(excess_buffer = calloc(bytes_to_transfer, sizeof(char)), NULL);

	off_in = off_out = 0;
	err = splice(in_fd, &off_in, out_fd, &off_out, bytes_to_transfer / 2,
				 excess_buffer, &excess_size);
	ATF_CHECK_MSG(err >= 0, "%s\n%i:%s\n", "splice failed", err,
				  strerror(errno));

	/* return the number of bytes unread */
	bytes_unread = (size_t)err;

	fprintf(stderr, "off_in: %li\noff_out: %li\n", off_in, off_out);

	/* making sure file offsets haven't changed */
	ATF_REQUIRE(lseek(in_fd, 0, SEEK_CUR) == 0);
	ATF_REQUIRE(lseek(out_fd, 0, SEEK_CUR) == 0);

	success_check(bytes_to_transfer / 2, excess_size, bytes_unread);
	write_out_excess(excess_buffer, excess_size, &off_out);
	success_check(bytes_to_transfer / 2, 0, bytes_unread);

	ATF_CHECK(off_in == off_out);
	ATF_REQUIRE(off_in == (off_t)bytes_to_transfer / 2);

	err = splice(in_fd, &off_in, out_fd, &off_out, bytes_to_transfer / 2,
				 excess_buffer, &excess_size);
	ATF_CHECK_MSG(err >= 0, "%s\n%i:%s\n", "splice failed", err,
				  strerror(errno));

	/* return the number of bytes unread */
	bytes_unread = (size_t)err;

	fprintf(stderr, "off_in: %li\noff_out: %li\n", off_in, off_out);

	/* making sure file offsets haven't changed */
	ATF_REQUIRE(lseek(in_fd, 0, SEEK_CUR) == 0);
	ATF_REQUIRE(lseek(out_fd, 0, SEEK_CUR) == 0);

	success_check(bytes_to_transfer, excess_size, bytes_unread);
	write_out_excess(excess_buffer, excess_size, &off_out);
	success_check(bytes_to_transfer, 0, bytes_unread);

	ATF_CHECK(off_in == off_out);
	ATF_REQUIRE(off_in == (off_t)bytes_to_transfer);

	free(excess_buffer);
}

ATF_TC_CLEANUP(regularfile_splice_check2, tc)
{
	if (close(in_fd) != 0)
		printf("close\n");
	if (close(out_fd) != 0)
		printf("close\n");
	unlink("read");
	unlink("write");
}

ATF_TC_WITH_CLEANUP(pipe_checks);

ATF_TC_HEAD(pipe_checks, tc)
{
	atf_tc_set_md_var(
		tc, "descr",
		"write data from a regular file to a pipe and try to read it");
}

ATF_TC_BODY(pipe_checks, tc)
{
	char *excess_buffer = NULL;
	int err, pipe_buf_space, pipefd[2];
	size_t bytes_to_transfer, bytes_unread, excess_data = 0, excess_size = 0,
			overflow = 20;

	ATF_REQUIRE(pipe(pipefd) == 0);

	err = ioctl(pipefd[1], FIONSPACE, &pipe_buf_space);
	ATF_REQUIRE(err == 0);

	bytes_to_transfer = preparation(pipe_buf_space + overflow);
	ATF_REQUIRE(bytes_to_transfer > (size_t)pipe_buf_space);

	overflow = bytes_to_transfer - (size_t)pipe_buf_space;
	ATF_REQUIRE(overflow > 0);

	/* allocated with calloc() to initialise the characters with '\0' */
	REQUIRE_LIBC(excess_buffer = calloc(bytes_to_transfer, sizeof(char)), NULL);

	err = splice(in_fd, NULL, pipefd[1], NULL, bytes_to_transfer, excess_buffer,
				 &excess_size);
	ATF_REQUIRE_MSG(err >= 0, "%s\n%i:%s\n", "splice failed", err,
					strerror(errno));

	/* return the number of bytes unread */
	bytes_unread = (size_t)err;
	ATF_CHECK(bytes_unread == 0);
	ATF_REQUIRE(excess_size >= overflow);

	excess_data = excess_size + bytes_unread;
	memset(excess_buffer, '\0', excess_size);
	excess_size = 0;

	ATF_REQUIRE(close(pipefd[1]) == 0);

	err = splice(pipefd[0], NULL, out_fd, NULL, bytes_to_transfer,
				 excess_buffer, &excess_size);
	ATF_CHECK_MSG(err >= 0, "%s\n%i:%s\n", "splice failed", err,
				  strerror(errno));

	bytes_unread = (size_t)err;
	ATF_REQUIRE(bytes_unread >= excess_data);
	ATF_CHECK(excess_size == 0);
	success_check((bytes_to_transfer - excess_data), excess_size,
				  (bytes_unread - excess_data));

	ATF_REQUIRE(close(pipefd[0]) == 0);
	free(excess_buffer);
}

ATF_TC_CLEANUP(pipe_checks, tc)
{
	if (close(in_fd) != 0)
		printf("close\n");
	if (close(out_fd) != 0)
		printf("close\n");
	unlink("read");
	unlink("write");
}

ATF_TC_WITH_CLEANUP(failing_checks);

ATF_TC_HEAD(failing_checks, tc)
{
	atf_tc_set_md_var(tc, "descr", "making sure the expected errors occur");
}

ATF_TC_BODY(failing_checks, tc)
{
	char *excess_buffer = NULL;
	int fd_invalid, fd_permission, pipefd[2];
	off_t offset;
	size_t bytes_to_transfer, excess_size = 0;

	bytes_to_transfer = preparation(54);
	ATF_REQUIRE(bytes_to_transfer > 0);

	REQUIRE_LIBC(excess_buffer = calloc(bytes_to_transfer, sizeof(char)), NULL);

	/* for regular files */
	errno = 0;
	fd_invalid = -1;
	fprintf(stderr, "about to call\n");
	ATF_REQUIRE_ERRNO(EBADF,
					  splice(fd_invalid, NULL, out_fd, NULL, bytes_to_transfer,
							 excess_buffer, &excess_size) == -1);

	ATF_REQUIRE_ERRNO(EBADF,
					  splice(in_fd, NULL, fd_invalid, NULL, bytes_to_transfer,
							 excess_buffer, &excess_size) == -1);

	/* pipes */
	ATF_REQUIRE(pipe(pipefd) == 0);
	offset = 10;

	ATF_REQUIRE_ERRNO(ESPIPE,
					  splice(in_fd, NULL, pipefd[1], &offset, bytes_to_transfer,
							 excess_buffer, &excess_size) == -1);

	ATF_REQUIRE_ERRNO(ESPIPE, splice(pipefd[0], &offset, out_fd, NULL,
									 bytes_to_transfer, excess_buffer,
									 &excess_size) == -1);

	ATF_CHECK_ERRNO(EINVAL,
					splice(pipefd[0], NULL, pipefd[0], NULL, bytes_to_transfer,
						   excess_buffer, &excess_size) == -1);

	fd_permission = open("temp", O_CREAT);

	ATF_CHECK_ERRNO(EBADF,
					splice(fd_permission, NULL, out_fd, NULL, bytes_to_transfer,
						   excess_buffer, &excess_size) == -1);
	ATF_CHECK_ERRNO(EBADF,
					splice(in_fd, NULL, fd_permission, NULL, bytes_to_transfer,
						   excess_buffer, &excess_size) == -1);

	ATF_CHECK(close(fd_permission) == 0);
	ATF_CHECK(unlink("temp") == 0);
	free(excess_buffer);
}

ATF_TC_CLEANUP(failing_checks, tc)
{
	if (close(in_fd) != 0)
		printf("close\n");
	if (close(out_fd) != 0)
		printf("close\n");
	unlink("read");
	unlink("write");
}

static int
recv_sock_prep(struct addrinfo *hints)
{
	int err, listener;  // yes = 1;
	struct addrinfo *res, *res_p;

	/* AI_PASSIVE and hostname = NULL to set ai_add = INADDR_ANY */
	hints->ai_flags = AI_PASSIVE;

	err = getaddrinfo(NULL, PORT, hints, &res);
	ATF_REQUIRE(err != -1);

	for (res_p = res; (res_p); res_p = res_p->ai_next) {
		listener =
			socket(res_p->ai_family, res_p->ai_socktype, res_p->ai_protocol);

		if (listener < 0)
			continue;

		// ATF_CHECK(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes,
		// sizeof(int)) == -1);

		if (bind(listener, res_p->ai_addr, res_p->ai_addrlen) == 0)
			break;

		close(listener);
	}

	ATF_REQUIRE(res_p != NULL);

	freeaddrinfo(res);

	if (listen(listener, 10) == -1) {
		close(listener);
		return -1;
	}

	return listener;
}

ATF_TC_WITH_CLEANUP(socket_checks);

ATF_TC_HEAD(socket_checks, tc)
{
	atf_tc_set_md_var(tc, "descr", "splice data across socket descriptors");
}

ATF_TC_BODY(socket_checks, tc)
{

	char *excess_buffer = NULL;
	int err, pipefd[2], lsockfd, sender, receiver;
	size_t bytes_to_transfer, bytes_unread, excess_data = 0, excess_size = 0;
	struct addrinfo hints, *res = NULL, *res_p = NULL;
	struct sockaddr_storage sender_addr;
	socklen_t sender_len;

	bytes_to_transfer = preparation(57);
	ATF_REQUIRE(bytes_to_transfer > 0);

	REQUIRE_LIBC(excess_buffer = calloc(bytes_to_transfer, sizeof(char)), NULL);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	/* No AI_PASSIVE and hostname = NULL to set ai_add = loopback address */
	err = getaddrinfo(NULL, PORT, &hints, &res);
	ATF_REQUIRE(err != -1);

	lsockfd = recv_sock_prep(&hints);
	ATF_REQUIRE(lsockfd != -1);

	/* pipe used to send size of excess to parent for checking */
	ATF_REQUIRE(pipe(pipefd) == 0);

	if (!fork()) {
		/* child process */

		close(pipefd[0]);

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

		ATF_REQUIRE(res_p != NULL);

		freeaddrinfo(res);

		/* The child needs to be sender so parent can do verification */
		/* this will never block */

		err = splice(in_fd, NULL, sender, NULL, bytes_to_transfer,
					 excess_buffer, &excess_size);
		ATF_REQUIRE_MSG(err != -1, "%s\n%i:%s\n", "splice failed in child", err,
						strerror(errno));

		excess_data = excess_size + (size_t)err;
		ATF_CHECK(write(pipefd[1], &excess_data, sizeof(size_t)) ==
				  sizeof(size_t));

		close(pipefd[1]);
		close(sender);
	}

	/* if the parent runs first, it will automatically block on accept(),
	 * forcing the child to run
	 */

	close(pipefd[1]);

	receiver = accept(lsockfd, (struct sockaddr *)&sender_addr, &sender_len);
	if (receiver == -1) {
		close(lsockfd);
		atf_tc_fail("couldn't accept the connection\n");
	}

	err = splice(receiver, NULL, out_fd, NULL, bytes_to_transfer, excess_buffer,
				 &excess_size);
	ATF_REQUIRE_MSG(err != -1, "%s\n%i:%s\n", "splice failed in parent", err,
					strerror(errno));

	bytes_unread = (size_t)err;

	/* make sure the child has sent that data */
	// waitpid(-1, NULL, 0);

	ATF_CHECK(read(pipefd[0], &excess_data, sizeof(size_t)) == sizeof(size_t));

	/* success_check() */
	ATF_REQUIRE(bytes_unread >= excess_data);
	success_check((bytes_to_transfer - excess_data), excess_size,
				  bytes_unread - excess_data);

	close(pipefd[0]);
	close(lsockfd);
	close(receiver);
}

ATF_TC_CLEANUP(socket_checks, tc)
{
	if (close(in_fd) != 0)
		printf("close\n");
	if (close(out_fd) != 0)
		printf("close\n");
	unlink("read");
	unlink("write");
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
