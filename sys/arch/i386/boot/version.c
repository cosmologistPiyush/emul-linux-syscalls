/*
 *	$Id: version.c,v 1.19 1994/03/30 11:19:28 cgd Exp $
 */

/*
 *	NOTE ANY CHANGES YOU MAKE TO THE BOOTBLOCKS HERE.
 *
 *	1.18 -> 1.19
 *		add a '-r' option, to specify RB_DFLTROOT
 *
 *	1.17 -> 1.18
 *		removed some more code we don't need for BDB. (mycroft)
 *
 *	1.16 -> 1.17
 *		removed with prejudice the extra buffer for xread(), changes
 *		to make the code smaller, and general cleanup. (mycroft)
 *
 *	1.15 -> 1.16
 *		reduce BUFSIZE to 4k, because that's fixed the
 *		boot problems, for some. (cgd)
 *
 *	1.14 -> 1.15
 *		seperated 'version' out from boot.c (cgd)
 *
 *	1.1 -> 1.14
 *		look in boot.c revision logs
 */

char *version = "$Revision: 1.19 $";
