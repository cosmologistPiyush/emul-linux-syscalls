/*	$NetBSD: oldmon.h,v 1.4 1994/11/20 20:53:16 deraadt Exp $ */

/*
 * Copyright (C) 1985 Regents of the University of California
 * Copyright (c) 1993 Adam Glass
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
 *	This product includes software developed by Adam Glass.
 * 4. The name of the Author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Adam Glass ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: Sprite /cdrom/src/kernel/Cvsroot/kernel/mach/sun3.md/machMon.h,v
 *	    9.1 90/10/03 13:52:34 mgbaker Exp SPRITE (Berkeley)
 */
#ifndef _MACHINE_OLDMON_H
#define _MACHINE_OLDMON_H

/*
 *     Structures, constants and defines for access to the sun monitor.
 *     These are translated from the sun monitor header file "sunromvec.h".
 *
 * The memory addresses for the PROM, and the EEPROM.
 * On the sun2 these addresses are actually 0x00EF??00
 * but only the bottom 24 bits are looked at so these still
 * work ok.
 */
#define PROM_BASE       0xffe81000

/*
 * The table entry that describes a device.  It exists in the PROM; a
 * pointer to it is passed in MachMonBootParam.  It can be used to locate
 * PROM subroutines for opening, reading, and writing the device.
 *
 * When using this interface, only one device can be open at once.
 *
 * NOTE: I am not sure what arguments boot, open, close, and strategy take.  
 * What is here is just translated verbatim from the sun monitor code.  We 
 * should figure this out eventually if we need it.
 */
struct om_boottable {
	char	devName[2];		/* The name of the device */
	int	(*probe)();		/* probe() --> -1 or found controller 
					   number */
	int	(*boot)();		/* boot(bp) --> -1 or start address */
	int	(*open)();		/* open(iobp) --> -1 or 0 */
	int	(*close)();		/* close(iobp) --> -1 or 0 */
	int	(*strategy)();		/* strategy(iobp,rw) --> -1 or 0 */
	char	*desc;			/* Printable string describing dev */
};

/*
 * Structure set up by the boot command to pass arguments to the program that
 * is booted.
 */
struct om_bootparam {
	char	*argPtr[8];		/* String arguments */
	char	strings[100];		/* String table for string arguments */
	char	devName[2];		/* Device name */
	int	ctlrNum;		/* Controller number */
	int	unitNum;		/* Unit number */
	int	partNum;		/* Partition/file number */
	char	*fileName;		/* File name, points into strings */
	struct om_boottable *bootTable;	/* Points to table entry for device */
};

/*
 * Here is the structure of the vector table which is at the front of the boot
 * rom.  The functions defined in here are explained below.
 *
 * NOTE: This struct has references to the structures keybuf and globram which
 *       I have not translated.  If anyone needs to use these they should
 *       translate these structs into Sprite format.
 */
struct om_vector {
	char	*initSp;		/* Initial system stack ptr for hardware */
	int	(*startMon)();		/* Initial PC for hardware */
	int	*diagberr;		/* Bus err handler for diags */

	/* Monitor and hardware revision and identification */
	struct om_bootparam **bootParam;	/* Info for bootstrapped pgm */
 	u_long	*memorySize;		/* Usable memory in bytes */

	/* Single-character input and output */
	int	(*getChar)(void);	/* Get char from input source */
	void	(*putChar)(int);	/* Put char to output sink */
	int	(*mayGet)(void);	/* Maybe get char, or -1 */
	int	(*mayPut)(int);		/* Maybe put char, or -1 */
	u_char	*echo;			/* Should getchar echo? */
	u_char	*inSource;		/* Input source selector */
	u_char	*outSink;		/* Output sink selector */
#define	PROMDEV_KBD	0		/* input from keyboard */
#define	PROMDEV_SCREEN	0		/* output to screen */
#define	PROMDEV_TTYA	1		/* in/out to ttya */
#define	PROMDEV_TTYB	2		/* in/out to ttyb */

	/* Keyboard input (scanned by monitor nmi routine) */
	int	(*getKey)();		/* Get next key if one exists */
	int	(*initGetKey)();	/* Initialize get key */
	u_int	*translation;		/* Kbd translation selector */
	u_char	*keyBid;		/* Keyboard ID byte */
	int	*screen_x;		/* V2: Screen x pos (R/O) */
	int	*screen_y;		/* V2: Screen y pos (R/O) */
	struct keybuf	*keyBuf;	/* Up/down keycode buffer */

	/* Monitor revision level. */
	char	*monId;

	/* Frame buffer output and terminal emulation */
	int	(*fbWriteChar)();	/* Write a character to FB */
	int	*fbAddr;		/* Address of frame buffer */
	char	**font;			/* Font table for FB */
	void	(*fbWriteStr)(char *, int); /* Quickly write string to FB */

	/* Reboot interface routine -- resets and reboots system. */
	void	(*reBoot)(char *);	/* e.g. reBoot("xy()vmunix") */

	/* Line input and parsing */
	u_char	*lineBuf;		/* The line input buffer */
	u_char	**linePtr;		/* Cur pointer into linebuf */
	int	*lineSize;		/* length of line in linebuf */
	int	(*getLine)();		/* Get line from user */
	u_char	(*getNextChar)();	/* Get next char from linebuf */
	u_char	(*peekNextChar)();	/* Peek at next char */
	int	*fbThere;		/* =1 if frame buffer there */
	int	(*getNum)();		/* Grab hex num from line */

	/* Print formatted output to current output sink */
	int	(*printf)();		/* Similar to "Kernel printf" */
	int	(*printHex)();		/* Format N digits in hex */

	/* Led stuff */
	u_char	*leds;			/* RAM copy of LED register */
	int	(*setLeds)();		/* Sets LED's and RAM copy */

	/* Non-maskable interrupt  (nmi) information */ 
	int	(*nmiAddr)();		/* Addr for level 7 vector */
	void	(*abortEntry)(void);	/* Entry for keyboard abort */
	int	*nmiClock;		/* Counts up in msec */

	/* Frame buffer type: see <machine/fbio.h> */
	int	*fbType;

	/* Assorted other things */
	u_long	romvecVersion;		/* Version # of Romvec */ 
	struct globram *globRam;	/* monitor global variables */
	caddr_t	kbdZscc;		/* Addr of keyboard in use */

	int	*keyrInit;		/* ms before kbd repeat */
	u_char	*keyrTick; 		/* ms between repetitions */
	u_long	*memoryAvail;		/* V1: Main mem usable size */
	long	*resetAddr;		/* where to jump on a reset */
	long	*resetMap;		/* pgmap entry for resetaddr */
					/* Really struct pgmapent *  */

	__dead void (*exitToMon)(void);	/* Exit from user program */
	u_char	**memorybitmap;		/* V1: &{0 or &bits} */
	void	(*setcxsegmap)();	/* Set seg in any context */
	void	(**vector_cmd)();	/* V2: Handler for 'v' cmd */
  	u_long	*ExpectedTrapSig;
  	u_long	*TrapVectorTable;
	int	dummy1z;
	int	dummy2z;
	int	dummy3z;
	int	dummy4z;
};

#define	romVectorPtr	((struct om_vector *)PROM_BASE)

#define mon_printf (romVectorPtr->printf)
#define mon_putchar (romVectorPtr->putChar)
#define mon_may_getchar (romVectorPtr->mayGet)
#define mon_exit_to_mon (romVectorPtr->exitToMon)
#define mon_reboot (romVectorPtr->exitToMon)
#define mon_panic(x) { mon_printf(x); mon_exit_to_mon();}

#define mon_setcxsegmap(context, va, sme) \
    romVectorPtr->setcxsegmap(context, va, sme)
#define romp (romVectorPtr)

/*
 * OLDMON_STARTVADDR and OLDMON_ENDVADDR denote the range of the damn monitor.
 * 
 * supposedly you can steal pmegs within this range that do not contain
 * valid pages. 
 */
#define OLDMON_STARTVADDR	0xFFD00000
#define OLDMON_ENDVADDR		0xFFF00000

/*
 * These describe the monitor's short segment which it basically uses to map
 * one stupid page that it uses for storage.  MONSHORTPAGE is the page,
 * and MONSHORTSEG is the segment that it is in.  If this sounds dumb to
 * you, it is.  I can change the pmeg, but not the virtual address.
 * Sun defines these with the high nibble set to 0xF.  I believe this was
 * for the monitor source which accesses this piece of memory with addressing
 * limitations or some such crud.  I haven't replicated this here, because
 * it is confusing, and serves no obvious purpose if you aren't the monitor.
 *
 */
#define MONSHORTPAGE	0x0FFFE000
#define MONSHORTSEG	0x0FFE0000

#endif /* MACHINE_OLDMON_H */
