#! /bin/sh
#
#	$NetBSD: makewhatis.sh,v 1.12 1998/02/09 01:34:57 lukem Exp $
#
# written by matthew green <mrg@eterna.com.au>, based on the
# original by J.T. Conklin <jtc@netbsd.org> and Thorsten
# Frueauf <frueauf@ira.uka.de>.
#
# Public domain.
#

LIST=/tmp/makewhatislist$$
TMP=/tmp/whatis$$
trap "rm -f $LIST $TMP; exit 1" 1 2 15

MANDIR=${1-/usr/share/man}
if test ! -d "$MANDIR"; then 
	echo "makewhatis: $MANDIR: not a directory"
	exit 1
fi

find $MANDIR \( -type f -o -type l \) -name '*.[0-9]*' -ls | \
    sort -n | awk '{if (u[$1]) next; u[$1]++ ; print $11}' > $LIST
 
egrep '\.[1-9]$' $LIST | xargs /usr/libexec/getNAME | \
	sed -e 's/ [a-zA-Z0-9]* \\-/ -/' > $TMP

egrep '\.0$' $LIST | while read file
do
	sed -n -f /usr/share/man/makewhatis.sed $file;
done >> $TMP

egrep '\.[0].(gz|Z)$' $LIST | while read file
do
	gzip -fdc $file | sed -n -f /usr/share/man/makewhatis.sed;
done >> $TMP

sort -u -o $TMP $TMP

make -f - install <<_Install_Whatis_Db_
FILES=$TMP
FILESDIR=$MANDIR
FILESNAME=whatis.db
NOOBJ=noobj

.include <bsd.prog.mk>
_Install_Whatis_Db_

rm -f $LIST $TMP
exit 0
