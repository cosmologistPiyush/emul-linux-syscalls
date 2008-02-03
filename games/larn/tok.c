/*	$NetBSD: tok.c,v 1.8 2008/02/03 20:01:24 dholland Exp $	*/

/* tok.c		Larn is copyrighted 1986 by Noah Morgan. */
#include <sys/cdefs.h>
#ifndef lint
__RCSID("$NetBSD: tok.c,v 1.8 2008/02/03 20:01:24 dholland Exp $");
#endif				/* not lint */

#include <sys/types.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include "header.h"
#include "extern.h"

static char     lastok = 0;
int             yrepcount = 0;
#ifndef FLUSHNO
#define FLUSHNO 5
#endif	/* FLUSHNO */
static int      flushno = FLUSHNO;	/* input queue flushing threshold */
#define MAXUM 52		/* maximum number of user re-named monsters */
#define MAXMNAME 40		/* max length of a monster re-name */
static char     usermonster[MAXUM][MAXMNAME];	/* the user named monster
						 * name goes here */
static u_char     usermpoint = 0;	/* the user monster pointer */

/*
	lexical analyzer for larn
 */
int
yylex()
{
	char            cc;
	int             ic;
	if (hit2flag) {
		hit2flag = 0;
		yrepcount = 0;
		return (' ');
	}
	if (yrepcount > 0) {
		--yrepcount;
		return (lastok);
	} else
		yrepcount = 0;
	if (yrepcount == 0) {
		bottomdo();
		showplayer();
	}			/* show where the player is	 */
	lflush();
	while (1) {
		c[BYTESIN]++;
		if (ckpflag)
			if ((c[BYTESIN] % 400) == 0) {	/* check for periodic
							 * checkpointing */
#ifndef DOCHECKPOINTS
				savegame(ckpfile);
#else
				wait(0);	/* wait for other forks to
						 * finish */
				if (fork() == 0) {
					savegame(ckpfile);
					exit();
				}
#endif
			}
		do {		/* if keyboard input buffer is too big, flush
				 * some of it */
			ioctl(0, FIONREAD, &ic);
			if (ic > flushno)
				read(0, &cc, 1);
		}
		while (ic > flushno);

		if (read(0, &cc, 1) != 1)
			return (lastok = -1);

		if (cc == 'Y' - 64) {	/* control Y -- shell escape */
			resetscroll();
			clear();/* scrolling region, home, clear, no
				 * attributes */
			if ((ic = fork()) == 0) {	/* child */
				execl("/bin/csh", "/bin/csh", NULL);
				exit(1);
			}
			wait(0);
			if (ic < 0) {	/* error */
				write(2, "Can't fork off a shell!\n", 25);
				sleep(2);
			}
			setscroll();
			return (lastok = 'L' - 64);	/* redisplay screen */
		}
		if ((cc <= '9') && (cc >= '0')) {
			yrepcount = yrepcount * 10 + cc - '0';
		} else {
			if (yrepcount > 0)
				--yrepcount;
			return (lastok = cc);
		}
	}
}

/*
 *	flushall()		Function to flush all type-ahead in the input buffer
 */
void
flushall()
{
	char            cc;
	int             ic;
	for (;;) {		/* if keyboard input buffer is too big, flush
				 * some of it */
		ioctl(0, FIONREAD, &ic);
		if (ic <= 0)
			return;
		while (ic > 0) {
			read(0, &cc, 1);
			--ic;
		}		/* gobble up the byte */
	}
}

/*
	function to set the desired hardness
	enter with hard= -1 for default hardness, else any desired hardness
 */
void
sethard(hard)
	int             hard;
{
	int    j, k, i;
	j = c[HARDGAME];
	hashewon();
	if (restorflag == 0) {	/* don't set c[HARDGAME] if restoring game */
		if (hard >= 0)
			c[HARDGAME] = hard;
	} else
		c[HARDGAME] = j;/* set c[HARDGAME] to proper value if
				 * restoring game */

	if ((k = c[HARDGAME]) != 0)
		for (j = 0; j <= MAXMONST + 8; j++) {
			i = ((6 + k) * monster[j].hitpoints + 1) / 6;
			monster[j].hitpoints = (i < 0) ? 32767 : i;
			i = ((6 + k) * monster[j].damage + 1) / 5;
			monster[j].damage = (i > 127) ? 127 : i;
			i = (10 * monster[j].gold) / (10 + k);
			monster[j].gold = (i > 32767) ? 32767 : i;
			i = monster[j].armorclass - k;
			monster[j].armorclass = (i < -127) ? -127 : i;
			i = (7 * monster[j].experience) / (7 + k) + 1;
			monster[j].experience = (i <= 0) ? 1 : i;
		}
}

/*
	function to read and process the larn options file
 */
void
readopts()
{
	const char  *i;
	int    j, k;
	int             flag;
	flag = 1;		/* set to 0 if he specifies a name for his
				 * character */
	if (lopen(optsfile) < 0) {
		strcpy(logname, loginname);
		return;		/* user name if no character name */
	}
	i = " ";
	while (*i) {
		if ((i = lgetw()) == NULL)
			break;	/* check for EOF */
		while ((*i == ' ') || (*i == '\t'))
			i++;	/* eat leading whitespace */
		switch (*i) {
		case 'b':
			if (strcmp(i, "bold-objects") == 0)
				boldon = 1;
			break;

		case 'e':
			if (strcmp(i, "enable-checkpointing") == 0)
				ckpflag = 1;
			break;

		case 'i':
			if (strcmp(i, "inverse-objects") == 0)
				boldon = 0;
			break;

		case 'f':
			if (strcmp(i, "female") == 0)
				sex = 0;	/* male or female */
			break;

		case 'm':
			if (strcmp(i, "monster:") == 0) {	/* name favorite monster */
				if ((i = lgetw()) == 0)
					break;
				strlcpy(usermonster[usermpoint], i, MAXMNAME);
				if (usermpoint >= MAXUM)
					break;	/* defined all of em */
				if (isalpha(j = usermonster[usermpoint][0])) {
					for (k = 1; k < MAXMONST + 8; k++)	/* find monster */
						if (monstnamelist[k] == j) {
							monster[k].name = &usermonster[usermpoint++][0];
							break;
						}
				}
			} else if (strcmp(i, "male") == 0)
				sex = 1;
			break;

		case 'n':
			if (strcmp(i, "name:") == 0) {	/* defining players name */
				if ((i = lgetw()) == 0)
					break;
				strlcpy(logname, i, LOGNAMESIZE);
				flag = 0;
			} else if (strcmp(i, "no-introduction") == 0)
				nowelcome = 1;
			else if (strcmp(i, "no-beep") == 0)
				nobeep = 1;
			break;

		case 'p':
			if (strcmp(i, "process-name:") == 0) {
				if ((i = lgetw()) == 0)
					break;
				strlcpy(psname, i, PSNAMESIZE);
			} else if (strcmp(i, "play-day-play") == 0) {
				/* bypass time restrictions: ignored */
			}
			break;

		case 's':
			if (strcmp(i, "savefile:") == 0) {	/* defining savefilename */
				if ((i = lgetw()) == 0)
					break;
				strcpy(savefilename, i);
				flag = 0;
			}
			break;
		};
	}
	if (flag)
		strcpy(logname, loginname);
}
