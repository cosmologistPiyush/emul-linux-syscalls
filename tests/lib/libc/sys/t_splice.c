/* $NetBSD$ */

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
#include <sys/signal.h>
#include <sys/socket.h>
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
#include <splice.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "h_macros.h"

#define PORT    "3490"
#define CHECK   0
#define REQUIRE 1

static int in_fd, out_fd;
static int handler_hit;
pid_t pid;

static size_t
preparation(size_t size)
{
	char *buf = NULL;
	int error, fd;
	RL(fd = open("/dev/urandom", O_RDONLY, S_IRUSR));

	RL(in_fd = open("read", O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR));

	REQUIRE_LIBC(buf = malloc(size + 1), NULL);
	buf[size] = '\0';

	error = read(fd, buf, size);
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
success_check(size_t file_in_size, int severity)
{
	struct stat fd_out;

	ATF_REQUIRE_MSG(fsync(out_fd) == 0, "%s\n", "fsync failed");

	RL(fstat(out_fd, &fd_out));

	ATF_CHECK(fd_out.st_size > 0);

	/* fd_out size doesn't contain EOF */
	if (severity == CHECK)
		ATF_CHECK_MSG(file_in_size == (size_t)fd_out.st_size, "%s\n",
					  "splice unsuccessful");
	else if (severity == REQUIRE)
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

static void
file_to_file_noffset(size_t len)
{
	int err;
	size_t bytes_to_transfer;

	bytes_to_transfer = preparation(len);
	ATF_REQUIRE(bytes_to_transfer > 0);

	/* regular files */
	RL(err = splice(in_fd, NULL, out_fd, NULL, bytes_to_transfer));

	success_check((size_t)err, REQUIRE);
	success_check(bytes_to_transfer, CHECK);
}

ATF_TC_WITH_CLEANUP(file2file_splice_noffset1);

ATF_TC_HEAD(file2file_splice_noffset1, tc)
{
	atf_tc_set_md_var(tc, "descr",
					  "transfer small amount of data from one regular file \
					  to another without any offset");
}

ATF_TC_BODY(file2file_splice_noffset1, tc)
{
	file_to_file_noffset(47);
}

ATF_TC_CLEANUP(file2file_splice_noffset1, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(file2file_splice_noffset2);

ATF_TC_HEAD(file2file_splice_noffset2, tc)
{
	atf_tc_set_md_var(tc, "descr",
					  "transfer data more than MAXPHYS from one regular \
					  file to another without any offset");
}

ATF_TC_BODY(file2file_splice_noffset2, tc)
{
	size_t size_of_maxphys = 64 * 1024;
	file_to_file_noffset(size_of_maxphys + 100);
}

ATF_TC_CLEANUP(file2file_splice_noffset2, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(file2file_splice_noffset3);

ATF_TC_HEAD(file2file_splice_noffset3, tc)
{
	atf_tc_set_md_var(tc, "descr",
					  "transfer large amount of data from one regular \
					  file to another without any offset");
}

ATF_TC_BODY(file2file_splice_noffset3, tc)
{
	size_t one_gb = 1 * 1024 * 1024 * 1024;
	file_to_file_noffset(one_gb);
}

ATF_TC_CLEANUP(file2file_splice_noffset3, tc)
{
	cleanup();
}

static void
file_to_file_offset(size_t len)
{
	int err;
	off_t off_in, off_out;
	size_t bytes_to_transfer, data_transferred = 0;

	bytes_to_transfer = preparation(len);
	ATF_REQUIRE(bytes_to_transfer > 0);

	off_in = off_out = 0;
	RL(err = splice(in_fd, &off_in, out_fd, &off_out, bytes_to_transfer / 2));
	data_transferred += (size_t)err;

	/* making sure file offsets haven't changed */
	ATF_REQUIRE(lseek(in_fd, 0, SEEK_CUR) == 0);
	ATF_REQUIRE(lseek(out_fd, 0, SEEK_CUR) == 0);

	ATF_CHECK(off_in == off_out);
	ATF_REQUIRE(off_out == (off_t)data_transferred);

	success_check(data_transferred, REQUIRE);
	success_check(bytes_to_transfer / 2, CHECK);

	/* write the rest of the data */
	RL(err = splice(in_fd, &off_in, out_fd, &off_out,
					(bytes_to_transfer - data_transferred)));
	data_transferred += (size_t)err;

	/* making sure file offsets haven't changed */
	ATF_REQUIRE(lseek(in_fd, 0, SEEK_CUR) == 0);
	ATF_REQUIRE(lseek(out_fd, 0, SEEK_CUR) == 0);

	ATF_CHECK(off_in == off_out);
	ATF_REQUIRE(off_out == (off_t)data_transferred);

	success_check(data_transferred, REQUIRE);
	success_check(bytes_to_transfer, CHECK);
}

ATF_TC_WITH_CLEANUP(file2file_splice_offset1);

ATF_TC_HEAD(file2file_splice_offset1, tc)
{
	atf_tc_set_md_var(tc, "descr",
					  "transfer small amount of data from one regular file \
					  to another with offset specified for each");
}

ATF_TC_BODY(file2file_splice_offset1, tc)
{
	file_to_file_offset(47);
}

ATF_TC_CLEANUP(file2file_splice_offset1, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(file2file_splice_offset2);

ATF_TC_HEAD(file2file_splice_offset2, tc)
{
	atf_tc_set_md_var(tc, "descr",
					  "transfer data more than MAXPHYS from one regular \
					  file to another with offset specified for each");
}

ATF_TC_BODY(file2file_splice_offset2, tc)
{
	size_t size_of_maxphys = 64 * 1024;
	file_to_file_offset(size_of_maxphys + 100);
}

ATF_TC_CLEANUP(file2file_splice_offset2, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(file2file_splice_offset3);

ATF_TC_HEAD(file2file_splice_offset3, tc)
{
	atf_tc_set_md_var(tc, "descr",
					  "transfer large amount of data from one regular \
					  file to another with offset specified for each");
}

ATF_TC_BODY(file2file_splice_offset3, tc)
{
	size_t one_gb = 1 * 1024 * 1024 * 1024;
	file_to_file_offset(one_gb);
}

ATF_TC_CLEANUP(file2file_splice_offset3, tc)
{
	cleanup();
}

static void
pipe_splice_checks(size_t len, int choice)
{
	int err, pipe_buf_space, pipefd[2];
	size_t bytes_to_transfer;

	RL(pipe(pipefd));

	switch (choice) {
	case 1:
		ATF_REQUIRE(len != 0);
		bytes_to_transfer = preparation(len);
		ATF_REQUIRE(bytes_to_transfer > 0);
		break;
	case 2:
		ATF_CHECK(len == 0);
		RL(err = ioctl(pipefd[1], FIONSPACE, &pipe_buf_space));
		bytes_to_transfer = preparation(pipe_buf_space + 100);
		ATF_REQUIRE(bytes_to_transfer > (size_t)pipe_buf_space);
		break;
	default:
		atf_tc_fail("error in test case\n");
	}

	RL(pid = fork());
	if (!pid) {
		RL(close(pipefd[0]));

		RL(err = splice(in_fd, NULL, pipefd[1], NULL, bytes_to_transfer));

		RL(close(pipefd[1]));
		/* child finishes here */
	} else {

		RL(close(pipefd[1]));

		RL(err = splice(pipefd[0], NULL, out_fd, NULL, bytes_to_transfer));
		RL(close(pipefd[0]));

		wait(NULL);
		success_check((size_t)err, REQUIRE);
		success_check(bytes_to_transfer, CHECK);
	}
}

ATF_TC_WITH_CLEANUP(pipe_splice_check1);

ATF_TC_HEAD(pipe_splice_check1, tc)
{
	atf_tc_set_md_var(tc, "descr", "splice small amount of data between pipes");
}

ATF_TC_BODY(pipe_splice_check1, tc)
{
	pipe_splice_checks(47, 1);
}

ATF_TC_CLEANUP(pipe_splice_check1, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(pipe_splice_check2);

ATF_TC_HEAD(pipe_splice_check2, tc)
{
	atf_tc_set_md_var(tc, "descr",
					  "splice data more than pipe_buffer between pipes");
}

ATF_TC_BODY(pipe_splice_check2, tc)
{
	pipe_splice_checks(0, 2);
}

ATF_TC_CLEANUP(pipe_splice_check2, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(pipe_splice_check3);

ATF_TC_HEAD(pipe_splice_check3, tc)
{
	atf_tc_set_md_var(tc, "descr",
					  "splice data more than MAXPHYS between pipes");
}

ATF_TC_BODY(pipe_splice_check3, tc)
{
	size_t size_of_maxphys = 64 * 1024;
	pipe_splice_checks((size_of_maxphys + 100), 1);
}

ATF_TC_CLEANUP(pipe_splice_check3, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(pipe_splice_check4);

ATF_TC_HEAD(pipe_splice_check4, tc)
{
	atf_tc_set_md_var(tc, "descr", "splice large amount of data between pipes");
}

ATF_TC_BODY(pipe_splice_check4, tc)
{
	size_t two_mb = 2 * 1024 * 1024;
	pipe_splice_checks(two_mb, 1);
}

ATF_TC_CLEANUP(pipe_splice_check4, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(failing_splice_checks);

ATF_TC_HEAD(failing_splice_checks, tc)
{
	atf_tc_set_md_var(tc, "descr", "make sure the expected errors occur");
}

ATF_TC_BODY(failing_splice_checks, tc)
{
	int fd_invalid, fd_permission, pipefd[2];
	off_t offset;
	size_t bytes_to_transfer;

	bytes_to_transfer = preparation(54);
	ATF_REQUIRE(bytes_to_transfer > 0);

	/* for regular files */
	errno = 0;
	fd_invalid = -1;
	ATF_REQUIRE_ERRNO(
		EBADF, splice(fd_invalid, NULL, out_fd, NULL, bytes_to_transfer));

	ATF_REQUIRE_ERRNO(EBADF,
					  splice(in_fd, NULL, fd_invalid, NULL, bytes_to_transfer));

	fd_permission = open("temp", O_CREAT | O_WRONLY);
	ATF_CHECK_ERRNO(
		EBADF, splice(fd_permission, NULL, out_fd, NULL, bytes_to_transfer));
	RL(close(fd_permission));

	fd_permission = open("temp", O_CREAT | O_RDONLY);
	ATF_CHECK_ERRNO(
		EBADF, splice(in_fd, NULL, fd_permission, NULL, bytes_to_transfer));
	RL(close(fd_permission));
	RL(unlink("temp"));

	/* pipes */
	RL(pipe(pipefd));
	offset = 10;

	ATF_REQUIRE_ERRNO(
		ESPIPE, splice(in_fd, NULL, pipefd[1], &offset, bytes_to_transfer));

	ATF_REQUIRE_ERRNO(
		ESPIPE, splice(pipefd[0], &offset, out_fd, NULL, bytes_to_transfer));

	RL(close(pipefd[0]));
	RL(close(pipefd[1]));
}

ATF_TC_CLEANUP(failing_splice_checks, tc)
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

	if ((err = getaddrinfo(NULL, PORT, hints, &res)) == -1) {
		listener = -1;
		goto out;
	}

	for (res_p = res; (res_p); res_p = res_p->ai_next) {
		listener =
			socket(res_p->ai_family, res_p->ai_socktype, res_p->ai_protocol);

		if (listener < 0)
			continue;

		if (bind(listener, res_p->ai_addr, res_p->ai_addrlen) == 0)
			break;

		RL(close(listener));
	}

	if (res_p == NULL) {
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

static void
socket_splice_checks(size_t len, int choice)
{

	int err, lsockfd, sender, sock_space, receiver;
	size_t bytes_to_transfer;
	struct addrinfo hints, *res = NULL, *res_p = NULL;
	struct sockaddr_storage sender_addr;
	socklen_t sender_len;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	/* No AI_PASSIVE and hostname = NULL to set ai_add = loopback address */
	RL(err = getaddrinfo(NULL, PORT, &hints, &res));
	RL(lsockfd = recv_sock_prep(&hints));

	switch (choice) {
	case 1:
		ATF_REQUIRE(len != 0);
		bytes_to_transfer = preparation(len);
		ATF_REQUIRE(bytes_to_transfer > 0);
		break;
	case 2:
		ATF_CHECK(len == 0);
		RL(err = ioctl(lsockfd, FIONSPACE, &sock_space));
		bytes_to_transfer = preparation(sock_space + 100);
		ATF_REQUIRE(bytes_to_transfer > (size_t)sock_space);
		break;
	default:
		atf_tc_fail("error in test case\n");
	}

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

		if (!res_p) {
			freeaddrinfo(res);
			atf_tc_fail("couldn't connect to the parent\n");
		}
		freeaddrinfo(res);

		/* The child needs to be sender so parent can do verification */
		/* this will never block */

		RL(err = sendfile(in_fd, NULL, sender, bytes_to_transfer));

		RL(close(sender));
		exit(0);
		/* child finishes here */
	} else {

		/* if the parent runs first, it will automatically block on accept(),
		 * forcing the child to run
		 */

		receiver =
			accept(lsockfd, (struct sockaddr *)&sender_addr, &sender_len);
		if (receiver == -1) {
			close(lsockfd);
			atf_tc_fail("couldn't accept the connection\n");
		}

		RL(err = splice(receiver, NULL, out_fd, NULL, bytes_to_transfer));

		/* make sure the child has sent that data */
		waitpid(-1, NULL, 0);
		RL(close(receiver));
	}

	/* success_check() */
	success_check((size_t)err, REQUIRE);
	success_check(bytes_to_transfer, CHECK);

	RL(close(lsockfd));
}

ATF_TC_WITH_CLEANUP(socket_splice_sendfile_check1);

ATF_TC_HEAD(socket_splice_sendfile_check1, tc)
{
	atf_tc_set_md_var(tc, "descr",
					  "sendfile small amount of data and splice receive it");
}

ATF_TC_BODY(socket_splice_sendfile_check1, tc)
{
	socket_splice_checks(47, 1);
}

ATF_TC_CLEANUP(socket_splice_sendfile_check1, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(socket_splice_sendfile_check2);

ATF_TC_HEAD(socket_splice_sendfile_check2, tc)
{
	atf_tc_set_md_var(tc, "descr",
					  "sendfile data more than socket queue and splice receive \
					  it");
}

ATF_TC_BODY(socket_splice_sendfile_check2, tc)
{
	socket_splice_checks(0, 2);
}

ATF_TC_CLEANUP(socket_splice_sendfile_check2, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(socket_splice_sendfile_check3);

ATF_TC_HEAD(socket_splice_sendfile_check3, tc)
{
	atf_tc_set_md_var(tc, "descr",
					  "sendfile data more than MAXPHYS and splice receive it");
}

ATF_TC_BODY(socket_splice_sendfile_check3, tc)
{
	size_t size_of_maxphys = 64 * 1024;
	socket_splice_checks((size_of_maxphys + 100), 1);
}

ATF_TC_CLEANUP(socket_splice_sendfile_check3, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(socket_splice_sendfile_check4);

ATF_TC_HEAD(socket_splice_sendfile_check4, tc)
{
	atf_tc_set_md_var(tc, "descr",
					  "sendfile large amount of data and splice receive it");
}

ATF_TC_BODY(socket_splice_sendfile_check4, tc)
{
	size_t two_mb = 2 * 1024 * 1024;
	socket_splice_checks(two_mb, 1);
}

ATF_TC_CLEANUP(socket_splice_sendfile_check4, tc)
{
	cleanup();
}

static void
sighand(int signo)
{
	if (signo == SIGALRM)
		kill(pid, SIGINFO);

	if (signo == SIGINFO)
		handler_hit += 1;
}

ATF_TC_WITH_CLEANUP(splice_signal_check);

ATF_TC_HEAD(splice_signal_check, tc)
{
	atf_tc_set_md_var(
		tc, "descr", "write data from a regular file to a pipe and try to read \
					as much as possible, because the write gets interrupted by \
					a signal");
}

ATF_TC_BODY(splice_signal_check, tc)
{
	int err, pipefd[2], status;
	sigset_t asigset, emptysigset, osigset;
	struct sigaction act, oact;
	size_t bytes_to_transfer;

	RL(pipe(pipefd));

	bytes_to_transfer = preparation(2 * 1024 * 1024);
	ATF_REQUIRE(bytes_to_transfer > 0);

	RL(sigemptyset(&emptysigset));
	RL(sigemptyset(&asigset));
	RL(sigaddset(&asigset, SIGINFO));

	memset(&act, 0, sizeof(act));
	memset(&oact, 0, sizeof(oact));
	act.sa_handler = sighand;
	act.sa_flags = 0;
	RL(sigemptyset(&act.sa_mask));

	RL(sigaction(SIGALRM, &act, &oact));
	RL(sigaction(SIGINFO, &act, &oact));

	handler_hit = 0;

	RL(pid = fork());
	if (!pid) {
		RL(close(pipefd[1]));
		size_t chunk = 128 * 1024;
		size_t read = 0;

		RL(err = splice(pipefd[0], NULL, out_fd, NULL, chunk));
		fprintf(stderr, "first read in child: %i\n", err);
		read += (size_t)err;

		RL(sigprocmask(SIG_BLOCK, &asigset, &osigset));
		while (handler_hit == 0) {
			if (sigsuspend(&emptysigset) == -1 || errno == EINTR)
				break;
			// atf_tc_fail("sigsuspend(&emptysigset): %s",
			//     strerror(errno));
		}
		RL(sigprocmask(SIG_SETMASK, &osigset, NULL));

		chunk = bytes_to_transfer - read;
		RL(err = splice(pipefd[0], NULL, out_fd, NULL, chunk));
		read += (size_t)err;

		printf("data read: %li\n", read);
		printf("data expected: %li\n", bytes_to_transfer);
		success_check(read, REQUIRE);

		RL(close(pipefd[0]));

		exit(0);
		/* child finishes here */

	} else {

		RL(close(pipefd[0]));
		alarm(2);

		RL(err = splice(in_fd, NULL, pipefd[1], NULL, bytes_to_transfer));

		fprintf(stdout, "moved: %i\n", err);
		RL(close(pipefd[1]));

		waitpid(pid, &status, 0);
		ATF_REQUIRE_EQ(WEXITSTATUS(status), 0);
	}
}

ATF_TC_CLEANUP(splice_signal_check, tc)
{
	cleanup();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, file2file_splice_noffset1);
	ATF_TP_ADD_TC(tp, file2file_splice_noffset2);
	ATF_TP_ADD_TC(tp, file2file_splice_noffset3);
	ATF_TP_ADD_TC(tp, file2file_splice_offset1);
	ATF_TP_ADD_TC(tp, file2file_splice_offset2);
	ATF_TP_ADD_TC(tp, file2file_splice_offset3);
	ATF_TP_ADD_TC(tp, pipe_splice_check1);
	ATF_TP_ADD_TC(tp, pipe_splice_check2);
	ATF_TP_ADD_TC(tp, pipe_splice_check3);
	ATF_TP_ADD_TC(tp, pipe_splice_check4);
	ATF_TP_ADD_TC(tp, failing_splice_checks);
	ATF_TP_ADD_TC(tp, socket_splice_sendfile_check1);
	ATF_TP_ADD_TC(tp, socket_splice_sendfile_check2);
	ATF_TP_ADD_TC(tp, socket_splice_sendfile_check3);
	ATF_TP_ADD_TC(tp, socket_splice_sendfile_check4);
	ATF_TP_ADD_TC(tp, splice_signal_check);

	return atf_no_error();
}
