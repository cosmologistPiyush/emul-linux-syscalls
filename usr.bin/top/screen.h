/*	$NetBSD: screen.h,v 1.3 1999/04/12 06:02:26 ross Exp $	*/

/*
 *  top - a top users display for Unix 4.2
 *
 *  This file contains all the definitions necessary to use the hand-written
 *  screen package in "screen.c"
 */

#define TCputs(str)	tputs(str, 1, putstdout)
#define putcap(str)	(void)((str) != NULL ? TCputs(str) : 0)
#define Move_to(x, y)	TCputs(tgoto(cursor_motion, x, y))

/* declare return values for termcap functions */
#ifdef __NetBSD__
#include <termcap.h>
#else
char *tgetstr();
char *tgoto();
#endif

extern char ch_erase;		/* set to the user's erase character */
extern char ch_kill;		/* set to the user's kill  character */
extern char smart_terminal;     /* set if the terminal has sufficient termcap
				   capabilities for normal operation */

/* These are some termcap strings for use outside of "screen.c" */
extern char *cursor_motion;
extern char *clear_line;
extern char *clear_to_end;

/* rows and columns on the screen according to termcap */
extern int  screen_length;
extern int  screen_width;

void init_termcap __P((int));
void init_screen __P((void));
void end_screen __P((void));
void reinit_screen __P((void));
void get_screensize __P((void));
void standout __P((char *));
void clear __P((void));
int clear_eol __P((int));
void go_home __P((void));
void putstdout __P((int));
