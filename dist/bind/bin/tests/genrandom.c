/*	$NetBSD: genrandom.c,v 1.1.1.2 2005/12/21 19:51:32 christos Exp $	*/

/*
 * Copyright (C) 2000, 2001, 2003  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Id: genrandom.c,v 1.8.2.2 2003/10/09 07:32:35 marka Exp */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int
main(int argc, char **argv) {
	unsigned int bytes;
	unsigned int k;
	char *endp;
	FILE *fp;

	if (argc != 3) {
		printf("usage: genrandom k file\n");
		exit(1);
	}
	k = strtoul(argv[1], &endp, 10);
	if (*endp != 0) {
		printf("usage: genrandom k file\n");
		exit(1);
	}
	bytes = k << 10;

	fp = fopen(argv[2], "w");
	if (fp == NULL) {
		printf("failed to open %s\n", argv[2]);
		exit(1);
	}

#ifndef HAVE_ARC4RANDOM
	srand(0x12345678);
#endif
	while (bytes > 0) {
#ifndef HAVE_ARC4RANDOM
		unsigned short int x = (rand() & 0xFFFF);
#else
		unsigned short int x = (arc4random() & 0xFFFF);
#endif
		unsigned char c = x & 0xFF;
		if (putc(c, fp) == EOF) {
			printf("error writing to file\n");
			exit(1);
		}
		c = x >> 8;
		if (putc(c, fp) == EOF) {
			printf("error writing to file\n");
			exit(1);
		}
		bytes -= 2;
	}
	fclose(fp);

	return (0);
}
