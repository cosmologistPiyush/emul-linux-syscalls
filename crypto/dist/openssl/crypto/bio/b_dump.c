/* crypto/bio/b_dump.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

/* 
 * Stolen from tjh's ssl/ssl_trc.c stuff.
 */

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/bio.h>

#define TRUNCATE
#define DUMP_WIDTH	16
#define DUMP_WIDTH_LESS_INDENT(i) (DUMP_WIDTH-((i-(i>6?6:i)+3)/4))

int BIO_dump(BIO *bio, const char *s, int len)
	{
	return BIO_dump_indent(bio, s, len, 0);
	}

int BIO_dump_indent(BIO *bio, const char *s, int len, int indent)
	{
	int ret=0;
	char buf[288+1],tmp[20],str[128+1];
	int i,j,rows,trunc;
	unsigned char ch;
	int dump_width;
	
	trunc=0;
	
#ifdef TRUNCATE
	for(; (len > 0) && ((s[len-1] == ' ') || (s[len-1] == '\0')); len--) 
		trunc++;
#endif

	if (indent < 0)
		indent = 0;
	if (indent)
		{
		if (indent > 128) indent=128;
		memset(str,' ',indent);
		}
	str[indent]='\0';
	
	dump_width=DUMP_WIDTH_LESS_INDENT(indent);
	rows=(len/dump_width);
	if ((rows*dump_width)<len)
		rows++;
	for(i=0;i<rows;i++)
		{
		buf[0]='\0';	/* start with empty string */
		strlcpy(buf, str, sizeof(buf));
		snprintf(tmp, sizeof(tmp), "%04x - ", i * dump_width);
		strlcat(buf, tmp, sizeof(tmp));
		for(j=0;j<dump_width;j++)
			{
			if (((i*dump_width)+j)>=len)
				{
				strlcat(buf, "   ", sizeof(buf));
				}
			else
				{
				ch=((unsigned char)*(s+i*dump_width+j)) & 0xff;
				snprintf(tmp, sizeof(tmp), "%02x%c", ch,
				    j == 7 ? '-' : ' ');
				strlcat(buf, tmp, sizeof(buf));
				}
			}
		strlcat(buf, "  ", sizeof(buf));
		for(j=0;j<dump_width;j++)
			{
			if (((i*dump_width)+j)>=len)
				break;
			ch=((unsigned char)*(s+i*dump_width+j)) & 0xff;
#ifndef CHARSET_EBCDIC
			snprintf(tmp, sizeof(tmp), "%c",
			    ((ch >= ' ') && (ch <= '~')) ? ch : '.');
#else
			snprintf(tmp, sizeof(tmp), "%c",
			    ((ch >= os_toascii[' ']) && (ch <= os_toascii['~']))
			    ? os_toebcdic[ch] : '.');
#endif
			strlcat(buf, tmp, sizeof(buf));
			}
		strlcat(buf, "\n", sizeof(buf));
		/* if this is the last call then update the ddt_dump thing so that
		 * we will move the selection point in the debug window 
		 */
		ret+=BIO_write(bio,(char *)buf,strlen(buf));
		}
#ifdef TRUNCATE
	if (trunc > 0)
		{
		snprintf(buf, sizeof(buf), "%s%04x - <SPACES/NULS>\n", str,
		    len + trunc);
		ret+=BIO_write(bio,(char *)buf,strlen(buf));
		}
#endif
	return(ret);
	}
