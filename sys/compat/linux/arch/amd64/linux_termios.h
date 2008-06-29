/*	$NetBSD: linux_termios.h,v 1.3 2008/06/29 08:50:09 njoly Exp $ */

/*-
 * Copyright (c) 2005 Emmanuel Dreyfus, all rights reserved.
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
 *	This product includes software developed by Emmanuel Dreyfus
 * 4. The name of the author may not be used to endorse or promote 
 *    products derived from this software without specific prior written 
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE THE AUTHOR AND CONTRIBUTORS ``AS IS'' 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS 
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _AMD64_LINUX_TERMIOS_H
#define _AMD64_LINUX_TERMIOS_H

#define LINUX_NCC 8
#define LINUX_NCCS 19

#define LINUX_CBAUD	0010017
#define LINUX_B0	0000000
#define LINUX_B50	0000001
#define LINUX_B75	0000002
#define LINUX_B110	0000003
#define LINUX_B134	0000004
#define LINUX_B150	0000005
#define LINUX_B200	0000006
#define LINUX_B300	0000007
#define LINUX_B600	0000010
#define LINUX_B1200	0000011
#define LINUX_B1800	0000012
#define LINUX_B2400	0000013
#define LINUX_B4800	0000014
#define LINUX_B9600	0000015
#define LINUX_B19200	0000016
#define LINUX_B38400	0000017
#define LINUX_B57600	0010001
#define LINUX_B115200	0010002
#define LINUX_B230400	0010003

#define LINUX_NSPEEDS   16
#define LINUX_NXSPEEDS   3 

#define LINUX_IGNBRK	0000001
#define LINUX_BRKINT	0000002
#define LINUX_IGNPAR	0000004
#define LINUX_PARMRK	0000010
#define LINUX_INPCK	0000020
#define LINUX_ISTRIP	0000040
#define LINUX_INLCR	0000100  
#define LINUX_IGNCR	0000200  
#define LINUX_ICRNL	0000400  
#define LINUX_IUCLC	0001000  
#define LINUX_IXON	0002000  
#define LINUX_IXANY	0004000  
#define LINUX_IXOFF	0010000
#define LINUX_IMAXBEL	0020000
#define LINUX_IUTF8	0040000

#define LINUX_OPOST	0000001
#define LINUX_ONLCR	0000004
#define LINUX_XTABS	0014000

#define LINUX_CSIZE	0000060
#define LINUX_CS5	0000000
#define LINUX_CS6	0000020
#define LINUX_CS7	0000040
#define LINUX_CS8	0000060
#define LINUX_CSTOPB	0000100
#define LINUX_CREAD	0000200
#define LINUX_PARENB	0000400
#define LINUX_PARODD	0001000
#define LINUX_HUPCL	0002000
#define LINUX_CLOCAL	0004000
#define LINUX_CBAUDEX	0010000

#define LINUX_CRTSCTS	020000000000

#define LINUX_ISIG	0000001
#define LINUX_ICANON	0000002
#define LINUX_XCASE	0000004
#define LINUX_ECHO	0000010
#define LINUX_ECHOE	0000020  
#define LINUX_ECHOK	0000040  
#define LINUX_ECHONL	0000100  
#define LINUX_NOFLSH	0000200  
#define LINUX_TOSTOP	0000400  
#define LINUX_ECHOCTL	0001000
#define LINUX_ECHOPRT	0002000
#define LINUX_ECHOKE	0004000
#define LINUX_FLUSHO	0010000
#define LINUX_PENDIN	0040000
#define LINUX_IEXTEN	0100000

#define	LINUX_OLD_VINTR         LINUX_VINTR
#define	LINUX_OLD_VQUIT         LINUX_VQUIT
#define	LINUX_OLD_VERASE        LINUX_VERASE
#define	LINUX_OLD_VKILL         LINUX_VKILL
#define	LINUX_OLD_VEOF          LINUX_VEOF
#define	LINUX_OLD_VMIN          LINUX_VMIN
#define	LINUX_OLD_VEOL          LINUX_VEOL
#define	LINUX_OLD_VTIME         LINUX_VTIME
#define	LINUX_OLD_VEOL2         LINUX_VEOL2
#define	LINUX_OLD_VSWTC         LINUX_VSWTC

#define LINUX_VINTR		0
#define LINUX_VQUIT		1
#define LINUX_VERASE		2
#define LINUX_VKILL		3
#define LINUX_VEOF		4
#define LINUX_VTIME		5
#define LINUX_VMIN		6
#define LINUX_VSWTC		7
#define LINUX_VSTART		8
#define LINUX_VSTOP		9
#define LINUX_VSUSP		10
#define LINUX_VEOL		11
#define LINUX_VREPRINT		12
#define LINUX_VDISCARD		13
#define LINUX_VWERASE		14
#define LINUX_VLNEXT		15
#define LINUX_VEOL2		16

#define LINUX_TCGETS		_LINUX_IO('T', 0x01)
#define LINUX_TCSETS		_LINUX_IO('T', 0x02)
#define LINUX_TCSETSW		_LINUX_IO('T', 0x03)
#define LINUX_TCSETSF		_LINUX_IO('T', 0x04)
#define LINUX_TCGETA		_LINUX_IO('T', 0x05)
#define LINUX_TCSETA		_LINUX_IO('T', 0x06)
#define LINUX_TCSETAW		_LINUX_IO('T', 0x07)
#define LINUX_TCSETAF		_LINUX_IO('T', 0x08)
#define LINUX_TCSBRK		_LINUX_IO('T', 0x09)
#define LINUX_TCXONC		_LINUX_IO('T', 0x0A)
#define LINUX_TCFLSH		_LINUX_IO('T', 0x0B)
#define LINUX_TIOCEXCL		_LINUX_IO('T', 0x0C)
#define LINUX_TIOCNXCL		_LINUX_IO('T', 0x0D)
#define LINUX_TIOCSCTTY		_LINUX_IO('T', 0x0E)
#define LINUX_TIOCGPGRP		_LINUX_IO('T', 0x0F)
#define LINUX_TIOCSPGRP		_LINUX_IO('T', 0x10)
#define LINUX_TIOCOUTQ		_LINUX_IO('T', 0x11)
#define LINUX_TIOCSTI		_LINUX_IO('T', 0x12)
#define LINUX_TIOCGWINSZ	_LINUX_IO('T', 0x13)
#define LINUX_TIOCSWINSZ	_LINUX_IO('T', 0x14)
#define LINUX_TIOCMGET		_LINUX_IO('T', 0x15)
#define LINUX_TIOCMBIS		_LINUX_IO('T', 0x16)
#define LINUX_TIOCMBIC		_LINUX_IO('T', 0x17)
#define LINUX_TIOCMSET		_LINUX_IO('T', 0x18)
#define LINUX_TIOCGSOFTCAR	_LINUX_IO('T', 0x19)
#define LINUX_TIOCSSOFTCAR	_LINUX_IO('T', 0x1A)
#define LINUX_FIONREAD		_LINUX_IO('T', 0x1B)
#define LINUX_TIOCLINUX		_LINUX_IO('T', 0x1C)
#define LINUX_TIOCCONS		_LINUX_IO('T', 0x1D)
#define LINUX_TIOCGSERIAL	_LINUX_IO('T', 0x1E)
#define LINUX_TIOCSSERIAL	_LINUX_IO('T', 0x1F)
#define LINUX_TIOCPKT		_LINUX_IO('T', 0x20)
#define LINUX_FIONBIO		_LINUX_IO('T', 0x21)
#define LINUX_TIOCNOTTY		_LINUX_IO('T', 0x22)
#define LINUX_TIOCSETD		_LINUX_IO('T', 0x23)
#define LINUX_TIOCGETD		_LINUX_IO('T', 0x24)
#define LINUX_TCSBRKP		_LINUX_IO('T', 0x25)
#define LINUX_TIOCSBRK		_LINUX_IO('T', 0x27)
#define LINUX_TIOCCBRK		_LINUX_IO('T', 0x28)
#define LINUX_TIOCGSID		_LINUX_IO('T', 0x29)
#define LINUX_TIOCGPTN		_LINUX_IOR('T',0x30, unsigned int)
#define LINUX_TIOCSPTLCK	_LINUX_IOW('T',0x31, int)
#define LINUX_FIONCLEX		_LINUX_IO('T', 0x50)
#define LINUX_FIOCLEX		_LINUX_IO('T', 0x51)
#define LINUX_FIOASYNC		_LINUX_IO('T', 0x52)
#define LINUX_TIOCSERCONFIG	_LINUX_IO('T', 0x53)
#define LINUX_TIOCSERGWILD	_LINUX_IO('T', 0x54)
#define LINUX_TIOCSERSWILD	_LINUX_IO('T', 0x55)
#define LINUX_TIOCGLCKTRMIOS	_LINUX_IO('T', 0x56)
#define LINUX_TIOCSLCKTRMIOS	_LINUX_IO('T', 0x57)
#define LINUX_TIOCSERGSTRUCT	_LINUX_IO('T', 0x58)
#define LINUX_TIOCSERGETLSR	_LINUX_IO('T', 0x59)
#define LINUX_TIOCSERGETMULTI	_LINUX_IO('T', 0x5A)
#define LINUX_TIOCSERSETMULTI	_LINUX_IO('T', 0x5B)
#define LINUX_TIOCMIWAIT	_LINUX_IO('T', 0x5C)
#define LINUX_TIOCGICOUNT	_LINUX_IO('T', 0x5D)
#define LINUX_TIOCGHAYESESP	_LINUX_IO('T', 0x5E)
#define LINUX_TIOCSHAYESESP	_LINUX_IO('T', 0x5F)
#define LINUX_FIOQSIZE		_LINUX_IO('T', 0x60)


#endif /* !_AMD64_LINUX_TERMIOS_H */
