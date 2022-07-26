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
#include <sys/stat.h>
#include <sys/splice.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <paths.h>

ATF_TC(simple_splice_check);
ATF_TC_HEAD(simple_splice_check, tc)
{
	atf_tc_set_md_var(tc, "descr", "Performing elementary splice(2) checks");
}
ATF_TC_BODY(simple_splice_check, tc)
{
	char *excess_buffer;
	const char *file_contents = "The quick brown fox jumped over the wall";
	int err, in_fd, out_fd, ret;
	size_t bytes_unread, excess_size = 0, file_in_size, file_out_size;
	struct stat sb;


	excess_buffer = NULL;
	in_fd = open("read", O_CREAT|O_RDWR|O_TRUNC, S_IRUSR|S_IWUSR);
	ATF_REQUIRE_MSG(in_fd >= 0, "%s\n", "file to read has not been created");

	err = write(in_fd, file_contents, strlen(file_contents));
	ATF_REQUIRE_MSG((err > 0), "%s\n", "file to read from is empty");

	file_in_size = err;

	err = close(in_fd);
	ATF_REQUIRE_MSG((err == 0), "%s\n", "file close failed");

	in_fd = open("read", O_RDONLY, S_IRUSR);
	ATF_REQUIRE_MSG(in_fd >= 0, "%s\n", "file to read from doesn't exist");

	out_fd = open("write", O_CREAT|O_TRUNC|O_WRONLY|O_SYNC, S_IRUSR|S_IWUSR);
	ATF_REQUIRE(out_fd >= 0);

	err = splice(in_fd, out_fd, file_in_size, excess_buffer, &excess_size);
	ATF_CHECK_MSG(err >= 0, "%s\n%i:%s\n", "splice failed", err, strerror(err));

	bytes_unread = err;

	err = fstat(out_fd, &sb);
	ATF_REQUIRE(err == 0);

	/* -1 for EOF */
	file_out_size = (size_t)sb.st_size - 1;

	ATF_REQUIRE_MSG((file_in_size - file_out_size) == (excess_size + bytes_unread),
			"%s\n", "error in syscall implementation");

	while ((excess_size != 0) && ((ret = write (out_fd, excess_buffer, excess_size)) != 0)) {
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			perror("write");
			break;
		}
		excess_size -= ret;
		excess_buffer += ret;
	}

	ATF_REQUIRE_MSG((file_in_size - file_out_size) == bytes_unread,
			"%s\n", "error in syscall implementation");


	err = close(in_fd);
	ATF_CHECK(err == 0);
	err = close(out_fd);
	ATF_CHECK(err == 0);

}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, simple_splice_check);

	return atf_no_error();
}
