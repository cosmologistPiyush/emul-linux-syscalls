/*	$NetBSD: subr_userconf.c,v 1.13 2005/02/26 21:34:55 perry Exp $	*/

/*
 * Copyright (c) 1996 Mats O Jansson <moj@stacken.kth.se>
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Mats O Jansson.
 * 4. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	OpenBSD: subr_userconf.c,v 1.19 2000/01/08 23:23:37 d Exp
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: subr_userconf.c,v 1.13 2005/02/26 21:34:55 perry Exp $");

#include "opt_userconf.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/device.h>
#include <sys/malloc.h>
#include <sys/time.h>

#include <dev/cons.h>

extern struct cfdata cfdata[];

int userconf_base = 16;				/* Base for "large" numbers */
int userconf_maxdev = -1;			/* # of used device slots   */
int userconf_totdev = -1;			/* # of device slots        */
int userconf_maxlocnames = -1;			/* # of locnames            */
int userconf_cnt = -1;				/* Line counter for ...     */
int userconf_lines = 12;			/* ... # of lines per page  */
int userconf_histlen = 0;
int userconf_histcur = 0;
char userconf_history[1024];
int userconf_histsz = sizeof(userconf_history);
char userconf_argbuf[40];			/* Additional input         */
char userconf_cmdbuf[40];			/* Command line             */
char userconf_histbuf[40];

void userconf_init(void);
int userconf_more(void);
void userconf_modify(const char *, int*);
void userconf_hist_cmd(char);
void userconf_hist_int(int);
void userconf_hist_eoc(void);
void userconf_pnum(int);
void userconf_pdevnam(short);
void userconf_pdev(short);
int userconf_number(char *, int *);
int userconf_device(char *, int *, short *, short *);
void userconf_change(int);
void userconf_disable(int);
void userconf_enable(int);
void userconf_help(void);
void userconf_list(void);
void userconf_common_dev(char *, int, short, short, char);
void userconf_add_read(char *, char, char *, int, int *);
int userconf_parse(char *);

static int getsn(char *, int);

#define UC_CHANGE 'c'
#define UC_DISABLE 'd'
#define UC_ENABLE 'e'
#define UC_FIND 'f'
#define UC_SHOW 's'

char *userconf_cmds[] = {
	"base",		"b",
	"change",	"c",
	"disable",	"d",
	"enable",	"e",
	"exit",		"q",
	"find",		"f",
	"help",		"h",
	"list",		"l",
	"lines",	"L",
	"quit",		"q",
	"?",		"h",
	"",		 "",
};

void
userconf_init()
{
	int i;
	struct cfdata *cf;

	i = 0;
	for (cf = cfdata; cf->cf_name; cf++)
		i++;

	userconf_maxdev = i - 1;
	userconf_totdev = i - 1;
}

int
userconf_more()
{
	int quit = 0;
	char c = '\0';

	if (userconf_cnt != -1) {
		if (userconf_cnt == userconf_lines) {
			printf("-- more --");
			c = cngetc();
			userconf_cnt = 0;
			printf("\r            \r");
		}
		userconf_cnt++;
		if (c == 'q' || c == 'Q')
			quit = 1;
	}
	return (quit);
}

void
userconf_hist_cmd(cmd)
	char cmd;
{
	userconf_histcur = userconf_histlen;
	if (userconf_histcur < userconf_histsz) {
		userconf_history[userconf_histcur] = cmd;
		userconf_histcur++;
	}
}

void
userconf_hist_int(val)
	int val;
{
	snprintf(userconf_histbuf, sizeof(userconf_histbuf), " %d", val);
	if ((userconf_histcur + strlen(userconf_histbuf)) < userconf_histsz) {
		memcpy(&userconf_history[userconf_histcur],
		      userconf_histbuf,
		      strlen(userconf_histbuf));
		userconf_histcur = userconf_histcur + strlen(userconf_histbuf);
	}
}

void
userconf_hist_eoc()
{
	if (userconf_histcur < userconf_histsz) {
		userconf_history[userconf_histcur] = '\n';
		userconf_histcur++;
		userconf_histlen = userconf_histcur;
	}
}

void
userconf_pnum(val)
	int val;
{
	if (val > -2 && val < 16) {
		printf("%d",val);
	} else {
		switch (userconf_base) {
		case 8:
			printf("0%o",val);
			break;
		case 10:
			printf("%d",val);
			break;
		case 16:
		default:
			printf("0x%x",val);
			break;
		}
	}
}

void
userconf_pdevnam(dev)
	short dev;
{
	struct cfdata *cd;

	cd = &cfdata[dev];
	printf("%s", cd->cf_name);
	switch (cd->cf_fstate) {
	case FSTATE_NOTFOUND:
	case FSTATE_DNOTFOUND:
		printf("%d", cd->cf_unit);
		break;
	case FSTATE_FOUND:
		printf("*FOUND*");
		break;
	case FSTATE_STAR:
	case FSTATE_DSTAR:
		printf("*");
		break;
	default:
		printf("*UNKNOWN*");
		break;
	}
}

void
userconf_pdev(devno)
	short devno;
{
	struct cfdata *cd;
	const struct cfparent *cfp;
	int   *l;
	const char * const *ln;

	if (devno > userconf_maxdev) {
		printf("Unknown devno (max is %d)\n", userconf_maxdev);
		return;
	}

	cd = &cfdata[devno];

	printf("[%3d] ", devno);
	userconf_pdevnam(devno);
	printf(" at");
	cfp = cd->cf_pspec;
	if (cfp == NULL)
		printf(" root");
	else if (cfp->cfp_parent != NULL && cfp->cfp_unit != -1)
		printf(" %s%d", cfp->cfp_parent, cfp->cfp_unit);
	else
		printf(" %s?", cfp->cfp_parent != NULL ? cfp->cfp_parent
						       : cfp->cfp_iattr);
	switch (cd->cf_fstate) {
	case FSTATE_NOTFOUND:
	case FSTATE_FOUND:
	case FSTATE_STAR:
		break;
	case FSTATE_DNOTFOUND:
	case FSTATE_DSTAR:
		printf(" disable");
		break;
	default:
		printf(" ???");
		break;
	}
	l = cd->cf_loc;
	ln = cd->cf_locnames;
	while (ln && *ln) {
		printf(" %s ", *ln++);
		userconf_pnum(*l++);
	}
	printf("\n");
}

int
userconf_number(c, val)
	char *c;
	int *val;
{
	u_int num = 0;
	int neg = 0;
	int base = 10;

	if (*c == '-') {
		neg = 1;
		c++;
	}
	if (*c == '0') {
		base = 8;
		c++;
		if (*c == 'x' || *c == 'X') {
			base = 16;
			c++;
		}
	}
	while (*c != '\n' && *c != '\t' && *c != ' ' && *c != '\0') {
		u_char cc = *c;

		if (cc >= '0' && cc <= '9')
			cc = cc - '0';
		else if (cc >= 'a' && cc <= 'f')
			cc = cc - 'a' + 10;
		else if (cc >= 'A' && cc <= 'F')
			cc = cc - 'A' + 10;
		else
			return (-1);

		if (cc > base)
			return (-1);
		num = num * base + cc;
		c++;
	}

	if (neg && num > INT_MAX)	/* overflow */
		return (1);
	*val = neg ? - num : num;
	return (0);
}

int
userconf_device(cmd, len, unit, state)
	char *cmd;
	int *len;
	short *unit, *state;
{
	short u = 0, s = FSTATE_FOUND;
	int l = 0;
	char *c;

	c = cmd;
	while (*c >= 'a' && *c <= 'z') {
		l++;
		c++;
	}
	if (*c == '*') {
		s = FSTATE_STAR;
		c++;
	} else {
		while (*c >= '0' && *c <= '9') {
			s = FSTATE_NOTFOUND;
			u = u*10 + *c - '0';
			c++;
		}
	}
	while (*c == ' ' || *c == '\t' || *c == '\n')
		c++;

	if (*c == '\0') {
		*len = l;
		*unit = u;
		*state = s;
		return(0);
	}

	return(-1);
}

void
userconf_modify(item, val)
	const char *item;
	int  *val;
{
	int ok = 0;
	int a;
	char *c;

	while (!ok) {
		printf("%s [", item);
		userconf_pnum(*val);
		printf("] ? ");

		getsn(userconf_argbuf, sizeof(userconf_argbuf));

		c = userconf_argbuf;
		while (*c == ' ' || *c == '\t' || *c == '\n') c++;

		if (*c != '\0') {
			if (userconf_number(c, &a) == 0) {
				*val = a;
				ok = 1;
			} else {
				printf("Unknown argument\n");
			}
		} else {
			ok = 1;
		}
	}
}

void
userconf_change(devno)
	int devno;
{
	struct cfdata *cd;
	char c = '\0';
	int   *l;
	int   ln;
	const char * const *locnames;

	if (devno <=  userconf_maxdev) {

		userconf_pdev(devno);

		while (c != 'y' && c != 'Y' && c != 'n' && c != 'N') {
			printf("change (y/n) ?");
			c = cngetc();
			printf("\n");
		}

		if (c == 'y' || c == 'Y') {

			/* XXX add cmd 'c' <devno> */
			userconf_hist_cmd('c');
			userconf_hist_int(devno);

			cd = &cfdata[devno];
			l = cd->cf_loc;
			locnames = cd->cf_locnames;
			ln = 0;

			while (locnames[ln])
			{
				userconf_modify(locnames[ln], l);

				/* XXX add *l */
				userconf_hist_int(*l);

				ln++;
				l++;
			}

			printf("[%3d] ", devno);
			userconf_pdevnam(devno);
			printf(" changed\n");
			userconf_pdev(devno);

			/* XXX add eoc */
			userconf_hist_eoc();

		}
	} else {
		printf("Unknown devno (max is %d)\n", userconf_maxdev);
	}
}

void
userconf_disable(devno)
	int devno;
{
	int done = 0;

	if (devno <= userconf_maxdev) {
		switch (cfdata[devno].cf_fstate) {
		case FSTATE_NOTFOUND:
			cfdata[devno].cf_fstate = FSTATE_DNOTFOUND;
			break;
		case FSTATE_STAR:
			cfdata[devno].cf_fstate = FSTATE_DSTAR;
			break;
		case FSTATE_DNOTFOUND:
		case FSTATE_DSTAR:
			done = 1;
			break;
		default:
			printf("Error unknown state\n");
			break;
		}

		printf("[%3d] ", devno);
		userconf_pdevnam(devno);
		if (done) {
			printf(" already");
		} else {
			/* XXX add cmd 'd' <devno> eoc */
			userconf_hist_cmd('d');
			userconf_hist_int(devno);
			userconf_hist_eoc();
		}
		printf(" disabled\n");
	} else {
		printf("Unknown devno (max is %d)\n", userconf_maxdev);
	}
}

void
userconf_enable(devno)
	int devno;
{
	int done = 0;

	if (devno <= userconf_maxdev) {
		switch (cfdata[devno].cf_fstate) {
		case FSTATE_DNOTFOUND:
			cfdata[devno].cf_fstate = FSTATE_NOTFOUND;
			break;
		case FSTATE_DSTAR:
			cfdata[devno].cf_fstate = FSTATE_STAR;
			break;
		case FSTATE_NOTFOUND:
		case FSTATE_STAR:
			done = 1;
			break;
		default:
			printf("Error unknown state\n");
			break;
		}

		printf("[%3d] ", devno);
		userconf_pdevnam(devno);
		if (done) {
			printf(" already");
		} else {
			/* XXX add cmd 'e' <devno> eoc */
			userconf_hist_cmd('d');
			userconf_hist_int(devno);
			userconf_hist_eoc();
		}
		printf(" enabled\n");
	} else {
		printf("Unknown devno (max is %d)\n", userconf_maxdev);
	}
}

void
userconf_help()
{
	int j = 0, k;

	printf("command   args                description\n");
	while (*userconf_cmds[j] != '\0') {
		printf(userconf_cmds[j]);
		k = strlen(userconf_cmds[j]);
		while (k < 10) {
			printf(" ");
			k++;
		}
		switch (*userconf_cmds[j+1]) {
		case 'L':
			printf("[count]             number of lines before more");
			break;
		case 'b':
			printf("8|10|16             base on large numbers");
			break;
		case 'c':
			printf("devno|dev           change devices");
			break;
		case 'd':
			printf("devno|dev           disable devices");
			break;
		case 'e':
			printf("devno|dev           enable devices");
			break;
		case 'f':
			printf("devno|dev           find devices");
			break;
		case 'h':
			printf("                    this message");
			break;
		case 'l':
			printf("                    list configuration");
			break;
		case 'q':
			printf("                    leave userconf");
			break;
		default:
			printf("                    don't know");
			break;
		}
		printf("\n");
		j += 2;
	}
}

void
userconf_list()
{
	int i = 0;

	userconf_cnt = 0;

	while (cfdata[i].cf_name != NULL) {
		if (userconf_more())
			break;
		userconf_pdev(i++);
	}

	userconf_cnt = -1;
}

void
userconf_common_dev(dev, len, unit, state, routine)
	char *dev;
	int len;
	short unit, state;
	char routine;
{
	int i = 0;

	switch (routine) {
	case UC_CHANGE:
		break;
	default:
		userconf_cnt = 0;
		break;
	}

	while (cfdata[i].cf_name != NULL) {
		if (strlen(cfdata[i].cf_name) == len) {

			/*
			 * Ok, if device name is correct
			 *  If state == FSTATE_FOUND, look for "dev"
			 *  If state == FSTATE_STAR, look for "dev*"
			 *  If state == FSTATE_NOTFOUND, look for "dev0"
			 */
			if (strncasecmp(dev, cfdata[i].cf_name,
					len) == 0 &&
			    (state == FSTATE_FOUND ||
			     (state == FSTATE_STAR &&
			      (cfdata[i].cf_fstate == FSTATE_STAR ||
			       cfdata[i].cf_fstate == FSTATE_DSTAR)) ||
			     (state == FSTATE_NOTFOUND &&
			      cfdata[i].cf_unit == unit &&
			      (cfdata[i].cf_fstate == FSTATE_NOTFOUND ||
			       cfdata[i].cf_fstate == FSTATE_DNOTFOUND)))) {
				if (userconf_more())
					break;
				switch (routine) {
				case UC_CHANGE:
					userconf_change(i);
					break;
				case UC_ENABLE:
					userconf_enable(i);
					break;
				case UC_DISABLE:
					userconf_disable(i);
					break;
				case UC_FIND:
					userconf_pdev(i);
					break;
				default:
					printf("Unknown routine /%c/\n",
					    routine);
					break;
				}
			}
		}
		i++;
	}

	switch (routine) {
	case UC_CHANGE:
		break;
	default:
		userconf_cnt = -1;
		break;
	}
}

void
userconf_add_read(prompt, field, dev, len, val)
	char *prompt;
	char field;
	char *dev;
	int len;
	int *val;
{
	int ok = 0;
	int a;
	char *c;

	*val = -1;

	while (!ok) {
		printf("%s ? ", prompt);

		getsn(userconf_argbuf, sizeof(userconf_argbuf));

		c = userconf_argbuf;
		while (*c == ' ' || *c == '\t' || *c == '\n') c++;

		if (*c != '\0') {
			if (userconf_number(c, &a) == 0) {
				if (a > userconf_maxdev) {
					printf("Unknown devno (max is %d)\n",
					    userconf_maxdev);
				} else if (strncasecmp(dev,
				    cfdata[a].cf_name, len) != 0 &&
					field == 'a') {
					printf("Not same device type\n");
				} else {
					*val = a;
					ok = 1;
				}
			} else if (*c == '?') {
				userconf_common_dev(dev, len, 0,
				    FSTATE_FOUND, UC_FIND);
			} else if (*c == 'q' || *c == 'Q') {
				ok = 1;
			} else {
				printf("Unknown argument\n");
			}
		} else {
			ok = 1;
		}
	}
}

int
userconf_parse(cmd)
	char *cmd;
{
	char *c, *v;
	int i = 0, j = 0, k, a;
	short unit, state;

	c = cmd;
	while (*c == ' ' || *c == '\t')
		c++;
	v = c;
	while (*c != ' ' && *c != '\t' && *c != '\n' && *c != '\0') {
		c++;
		i++;
	}

	k = -1;
	while (*userconf_cmds[j] != '\0') {
		if (strlen(userconf_cmds[j]) == i) {
			if (strncasecmp(v, userconf_cmds[j], i) == 0)
				k = j;
		}
		j += 2;
	}

	while (*c == ' ' || *c == '\t' || *c == '\n')
		c++;

	if (k == -1) {
		if (*v != '\n')
			printf("Unknown command, try help\n");
	} else {
		switch (*userconf_cmds[k+1]) {
		case 'L':
			if (*c == '\0')
				printf("Argument expected\n");
			else if (userconf_number(c, &a) == 0)
				userconf_lines = a;
			else
				printf("Unknown argument\n");
			break;
		case 'b':
			if (*c == '\0')
				printf("8|10|16 expected\n");
			else if (userconf_number(c, &a) == 0) {
				if (a == 8 || a == 10 || a == 16) {
					userconf_base = a;
				} else {
					printf("8|10|16 expected\n");
				}
			} else
				printf("Unknown argument\n");
			break;
		case 'c':
			if (*c == '\0')
				printf("DevNo or Dev expected\n");
			else if (userconf_number(c, &a) == 0)
				userconf_change(a);
			else if (userconf_device(c, &a, &unit, &state) == 0)
				userconf_common_dev(c, a, unit, state, UC_CHANGE);
			else
				printf("Unknown argument\n");
			break;
		case 'd':
			if (*c == '\0')
				printf("Attr, DevNo or Dev expected\n");
			else if (userconf_number(c, &a) == 0)
				userconf_disable(a);
			else if (userconf_device(c, &a, &unit, &state) == 0)
				userconf_common_dev(c, a, unit, state, UC_DISABLE);
			else
				printf("Unknown argument\n");
			break;
		case 'e':
			if (*c == '\0')
				printf("Attr, DevNo or Dev expected\n");
			else if (userconf_number(c, &a) == 0)
				userconf_enable(a);
			else if (userconf_device(c, &a, &unit, &state) == 0)
				userconf_common_dev(c, a, unit, state, UC_ENABLE);
			else
				printf("Unknown argument\n");
			break;
		case 'f':
			if (*c == '\0')
				printf("DevNo or Dev expected\n");
			else if (userconf_number(c, &a) == 0)
				userconf_pdev(a);
			else if (userconf_device(c, &a, &unit, &state) == 0)
				userconf_common_dev(c, a, unit, state, UC_FIND);
			else
				printf("Unknown argument\n");
			break;
		case 'h':
			userconf_help();
			break;
		case 'l':
			if (*c == '\0')
				userconf_list();
			else
				printf("Unknown argument\n");
			break;
		case 'q':
			/* XXX add cmd 'q' eoc */
			userconf_hist_cmd('q');
			userconf_hist_eoc();
			return(-1);
		case 's':
		default:
			printf("Unknown command\n");
			break;
		}
	}
	return(0);
}

extern void user_config(void);

void
user_config()
{
	char prompt[] = "uc> ";

	userconf_init();
	printf("userconf: configure system autoconfiguration:\n");

	while (1) {
		printf(prompt);
		if (getsn(userconf_cmdbuf, sizeof(userconf_cmdbuf)) > 0 &&
		    userconf_parse(userconf_cmdbuf))
			break;
	}
	printf("Continuing...\n");
}

/*
 * XXX shouldn't this be a common function?
 */
static int
getsn(cp, size)
	char *cp;
	int size;
{
	char *lp;
	int c, len;

	cnpollc(1);

	lp = cp;
	len = 0;
	for (;;) {
		c = cngetc();
		switch (c) {
		case '\n':
		case '\r':
			printf("\n");
			*lp++ = '\0';
			cnpollc(0);
			return (len);
		case '\b':
		case '\177':
		case '#':
			if (len) {
				--len;
				--lp;
				printf("\b \b");
			}
			continue;
		case '@':
		case 'u'&037:
			len = 0;
			lp = cp;
			printf("\n");
			continue;
		default:
			if (len + 1 >= size || c < ' ') {
				printf("\007");
				continue;
			}
			printf("%c", c);
			++len;
			*lp++ = c;
		}
	}
}
