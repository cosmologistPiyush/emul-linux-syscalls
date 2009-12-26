#!/bin/sh
#
# Copyright (C) 2004, 2007, 2009  Internet Systems Consortium, Inc. ("ISC")
# Copyright (C) 2000, 2001  Internet Software Consortium.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

# Id: clean.sh,v 1.16 2009/10/27 05:57:06 each Exp

#
# Clean up after zone transfer tests.
#

rm -f dig.out.ns1 dig.out.ns2 dig.out.ns1.after ns1/*.jnl ns2/*.jnl \
    ns1/example.db ns1/update.db ns1/other.db ns1/ddns.key
rm -f random.data
rm -f ns2/example.bk
rm -f ns2/update.bk
rm -f */named.memstats
