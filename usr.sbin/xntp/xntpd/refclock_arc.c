/*
 * refclock_arc - clock driver for ARCRON MSF receivers
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#if defined(REFCLOCK) && defined(ARCRON_MSF)
    static const char arc_version[] = { "V1.1 1997/06/23" };

#undef ARCRON_DEBUG /* Define only while in development... */

#ifndef ARCRON_NOT_KEEN
#define ARCRON_KEEN 1 /* Be keen, and trusting of the clock, if defined. */
#endif

#ifndef ARCRON_NOT_OWN_FILTER
#ifndef ARCRON_OWN_FILTER
#undef ARCRON_OWN_FILTER /* Use own median filter only for versions before 3-5.90.1. */
#endif
#endif

#ifndef ARCRON_NOT_MULTIPLE_SAMPLES
#define ARCRON_MULTIPLE_SAMPLES 1 /* Use all timestamp bytes as samples. */
#endif

#ifndef ARCRON_NOT_LEAPSECOND_KEEN
#ifndef ARCRON_LEAPSECOND_KEEN
#undef ARCRON_LEAPSECOND_KEEN /* Respond quickly to leap seconds: doesn't work yet. */
#endif
#endif

/*
Code by Derek Mulcahy, <derek@toybox.demon.co.uk>, 1997.
Modifications by Damon Hart-Davis, <d@hd.org>, 1997.

THIS CODE IS SUPPLIED AS IS, WITH NO WARRANTY OF ANY KIND.  USE AT
YOUR OWN RISK.

Orginally developed and used with xntp3-5.85 by Derek Mulcahy.

Built against xntp3-5.90 on Solaris 2.5 using gcc 2.7.2.

This code may be freely copied and used and incorporated in other
systems providing the disclaimer and notice of authorship are
reproduced.

-------------------------------------------------------------------------------

Author's original note:

I enclose my xntp driver for the Galleon Systems Arc MSF receiver.

It works (after a fashion) on both Solaris-1 and Solaris-2.

I am currently using xntp3-5.85.  I have been running the code for
about 7 months without any problems.  Even coped with the change to BST!

I had to do some funky things to read from the clock because it uses the
power from the receive lines to drive the transmit lines.  This makes the
code look a bit stupid but it works.  I also had to put in some delays to
allow for the turnaround time from receive to transmit.  These delays
are between characters when requesting a time stamp so that shouldn't affect
the results too drastically.

...

The bottom line is that it works but could easily be improved.  You are
free to do what you will with the code.  I haven't been able to determine
how good the clock is.  I think that this requires a known good clock
to compare it against.

-------------------------------------------------------------------------------

Damon's notes for adjustments:

MAJOR CHANGES SINCE V1.0
========================
 1) Removal of pollcnt variable that made the clock go permanently
    off-line once two time polls failed to gain responses.

 2) Avoiding (at least on Solaris-2) terminal becoming the controlling
    terminal of the process when we do a low-level open().

 3) Additional logic (conditional on ARCRON_LEAPSECOND_KEEN being
    defined) to try to resync quickly after a potential leap-second
    insertion or deletion.

 4) Code significantly slimmer at run-time than V1.0.


GENERAL
=======

 1) The C preprocessor symbol to have the clock built has been changed
    from ARC to ARCRON_MSF to minimise the possiblity of clashes with
    other symbols in the future.

 2) PRECISION should be -4/-5 (63ms/31ms) for the following reasons:

     a) The ARC documentation claims the internal clock is (only)
        accurate to about 20ms relative to Rugby (plus there must be
        noticable drift and delay in the ms range due to transmission
        delays and changing atmospheric effects).  This clock is not
        designed for ms accuracy as NTP has spoilt us all to expect.

     b) The clock oscillator looks like a simple uncompensated quartz
        crystal of the sort used in digital watches (ie 32768Hz) which
        can have large temperature coefficients and drifts; it is not
        clear if this oscillator is properly disciplined to the MSF
        transmission, but as the default is to resync only once per
        *day*, we can imagine that it is not, and is free-running.  We
        can minimise drift by resyncing more often (at the cost of
        reduced battery life), but drift/wander may still be
        significant.

     c) Note that the bit time of 3.3ms adds to the potential error in
        the the clock timestamp, since the bit clock of the serial link
        may effectively be free-running with respect to the host clock
        and the MSF clock.  Actually, the error is probably 1/16th of
        the above, since the input data is probably sampled at at least
        16x the bit rate.

    By keeping the clock marked as not very precise, it will have a
    fairly large dispersion, and thus will tend to be used as a
    `backup' time source and sanity checker, which this clock is
    probably ideal for.  For an isolated network without other time
    sources, this clock can probably be expected to provide *much*
    better than 1s accuracy, which will be fine.

    By default, PRECISION is set to -4, but experience, especially at a
    particular geographic location with a particular clock, may allow
    this to be altered to -5.  (Note that skews of +/- 10ms are to be
    expected from the clock from time-to-time.)  This improvement of
    reported precision can be instigated by setting flag3 to 1, though
    the PRECISION will revert to the normal value while the clock
    signal quality is unknown whatever the flag3 setting.

    IN ANY CASE, BE SURE TO SET AN APPROPRIATE FUDGE FACTOR TO REMOVE
    ANY RESIDUAL SKEW, eg:

        server 127.127.27.0 # ARCRON MSF radio clock unit 0.
        # Fudge timestamps by about 20ms.
        fudge 127.127.27.0 time1 0.020

    You will need to observe your system's behaviour, assuming you have
    some other NTP source to compare it with, to work out what the
    fudge factor should be.  For my Sun SS1 running SunOS 4.1.3_U1 with
    my MSF clock with my distance from the MSF transmitter, +20ms
    seemed about right, after some observation.

 3) REFID has been made "MSFa" to reflect the MSF time source and the
    ARCRON receiver.

 4) DEFAULT_RESYNC_TIME is the time in seconds (by default) before
    forcing a resync since the last attempt.  This is picked to give a
    little less than an hour between resyncs and to try to avoid
    clashing with any regular event at a regular time-past-the-hour
    which might cause systematic errors.

    The INITIAL_RESYNC_DELAY is to avoid bothering the clock and
    running down its batteries unnecesarily if xntpd is going to crash
    or be killed or reconfigured quickly.  If ARCRON_KEEN is defined
    then this period is long enough for (with normal polling rates)
    enough time samples to have been taken to allow xntpd to sync to
    the clock before the interruption for the clock to resync to MSF.
    This avoids xntpd syncing to another peer first and then
    almost immediately hopping to the MSF clock.

    The RETRY_RESYNC_TIME is used before rescheduling a resync after a
    resync failed to reveal a statisfatory signal quality (too low or
    unknown).

 5) The clock seems quite jittery, so I have increased the
    median-filter size from the typical (previous) value of 3.  I
    discard up to half the results in the filter.  It looks like maybe
    1 sample in 10 or so (maybe less) is a spike, so allow the median
    filter to discard at least 10% of its entries or 1 entry, whichever
    is greater.

 6) Sleeping *before* each character sent to the unit to allow required
    inter-character time but without introducting jitter and delay in
    handling the response if possible.

 7) If the flag ARCRON_KEEN is defined, take time samples whenever
    possible, even while resyncing, etc.  We rely, in this case, on the
    clock always giving us a reasonable time or else telling us in the
    status byte at the end of the timestamp that it failed to sync to
    MSF---thus we should never end up syncing to completely the wrong
    time.

 8) If the flag ARCRON_OWN_FILTER is defined, use own versions of
    refclock median-filter routines to get round small bug in 3-5.90
    code which does not return the median offset.

 9) We would appear to have a year-2000 problem with this clock since
    it returns only the two least-significant digits of the year.  But
    xntpd ignores the year and uses the local-system year instead, so
    this is in fact not a problem.  Nevertheless, we attempt to do a
    sensible thing with the dates, wrapping them into a 100-year
    window.

 10)Logs stats information that can be used by Derek's Tcl/Tk utility
    to show the status of the clock.

 11)The clock documentation insists that the number of bits per
    character to be sent to the clock, and sent by it, is 11, including
    one start bit and two stop bits.  The data format is either 7+even
    or 8+none.


TO-DO LIST
==========

  * Eliminate use of scanf(), and maybe sprintf().

  * Allow user setting of resync interval to trade battery life for
    accuracy; maybe could be done via fudge factor or unit number.

  * Possibly note the time since the last resync of the MSF clock to
    MSF as the age of the last reference timestamp, ie trust the
    clock's oscillator not very much...

  * Add very slow auto-adjustment up to a value of +/- time2 to correct
    for long-term errors in the clock value (time2 defaults to 0 so the
    correction would be disabled by default).

  * Consider trying to use the tty_clk/ppsclock support.

  * Possibly use average or maximum signal quality reported during
    resync, rather than just the last one, which may be atypical.

*/


/* Notes for HKW Elektronik GmBH Radio clock driver */
/* Author Lyndon David, Sentinet Ltd, Feb 1997      */
/* These notes seem also to apply usefully to the ARCRON clock. */

/* The HKW clock module is a radio receiver tuned into the Rugby */
/* MSF time signal tranmitted on 60 kHz. The clock module connects */
/* to the computer via a serial line and transmits the time encoded */
/* in 15 bytes at 300 baud 7 bits two stop bits even parity */

/* Clock communications, from the datasheet */
/* All characters sent to the clock are echoed back to the controlling */
/* device. */
/* Transmit time/date information */
/* syntax ASCII o<cr> */
/* Character o may be replaced if neccesary by a character whose code */
/* contains the lowest four bits f(hex) eg */
/* syntax binary: xxxx1111 00001101 */

/* DHD note:
You have to wait for character echo + 10ms before sending next character.
*/

/* The clock replies to this command with a sequence of 15 characters */
/* which contain the complete time and a final <cr> making 16 characters */
/* in total. */
/* The RC computer clock will not reply immediately to this command because */
/* the start bit edge of the first reply character marks the beginning of */
/* the second. So the RC Computer Clock will reply to this command at the */
/* start of the next second */
/* The characters have the following meaning */
/* 1. hours tens   */
/* 2. hours units  */
/* 3. minutes tens */
/* 4. minutes units */
/* 5. seconds tens  */
/* 6. seconds units */
/* 7. day of week 1-monday 7-sunday */
/* 8. day of month tens */
/* 9. day of month units */
/* 10. month tens */
/* 11. month units */
/* 12. year tens */
/* 13. year units */
/* 14. BST/UTC status */
/*      bit 7   parity */
/*      bit 6   always 0 */
/*      bit 5   always 1 */
/*      bit 4   always 1 */
/*      bit 3   always 0 */
/*      bit 2   =1 if UTC is in effect, complementary to the BST bit */
/*      bit 1   =1 if BST is in effect, according to the BST bit     */
/*      bit 0   BST/UTC change impending bit=1 in case of change impending */
/* 15. status */
/*      bit 7   parity */
/*      bit 6   always 0 */
/*      bit 5   always 1 */
/*      bit 4   always 1 */
/*      bit 3   =1 if low battery is detected */
/*      bit 2   =1 if the very last reception attempt failed and a valid */
/*              time information already exists (bit0=1) */
/*              =0 if the last reception attempt was successful */
/*      bit 1   =1 if at least one reception since 2:30 am was successful */
/*              =0 if no reception attempt since 2:30 am was successful */
/*      bit 0   =1 if the RC Computer Clock contains valid time information */
/*              This bit is zero after reset and one after the first */
/*              successful reception attempt */

/* DHD note:
Also note g<cr> command which confirms that a resync is in progress, and
if so what signal quality (0--5) is available.
Also note h<cr> command which starts a resync to MSF signal.
*/



#include <stdio.h>
#include <ctype.h>
#include <sys/time.h>

#if defined(HAVE_BSD_TTYS)
#include <sgtty.h>
#endif /* HAVE_BSD_TTYS */

#if defined(HAVE_SYSV_TTYS)
#include <termio.h>
#endif /* HAVE_SYSV_TTYS */

#if defined(HAVE_TERMIOS)
#include <termios.h>
#endif

#include "ntpd.h"
#include "ntp_io.h"
#include "ntp_refclock.h"
#include "ntp_stdlib.h"

/*
 * This driver supports the ARCRON MSF Radio Controlled Clock
 */

/*
 * Interface definitions
 */
#define DEVICE          "/dev/arc%d"    /* Device name and unit. */
#define SPEED           B300            /* UART speed (300 baud) */
#define PRECISION       (-4)            /* Precision  (~63 ms). */
#define HIGHPRECISION   (-5)            /* If things are going well... */
#define REFID           "MSFa"          /* Reference ID. */
#define DESCRIPTION     "ARCRON MSF Receiver"

#define NSAMPLES        4               /* Stages of median filter. */
#define NSAMPLESLONG    8               /* Stages of long filter. */

#define LENARC          16              /* Format `o' timecode length. */

#define BITSPERCHAR     11              /* Bits per character. */
#define BITTIME         0x0DA740E       /* Time for 1 bit at 300bps. */
#define CHARTIME10      0x8888888       /* Time for 10-bit char at 300bps. */
#define CHARTIME11      0x962FC96       /* Time for 11-bit char at 300bps. */
#define CHARTIME                        /* Time for char at 300bps. */ \
    ( (BITSPERCHAR == 11) ? CHARTIME11 : ( (BITSPERCHAR == 10) ? CHARTIME10 : \
            (BITSPERCHAR * BITTIME) ) )

/* Allow for UART to accept char half-way through final stop bit. */
#define INITIALOFFSET (-BITTIME/2)

    /*
    charoffsets[x] is the time after the start of the second that byte
    x (with the first byte being byte 1) is received by the UART,
    assuming that the initial edge of the start bit of the first byte
    is on-time.  The values are represented as the fractional part of
    an l_fp.

    We store enough values to have the offset of each byte including
    the trailing \r, on the assumption that the bytes follow one
    another without gaps.
    */
    static const u_int32 charoffsets[LENARC+1] = {
#if BITSPERCHAR == 11 /* Usual case. */
    /* Offsets computed as accurately as possible... */
    0,
    INITIALOFFSET + 0x0962fc96, /*  1 chars,  11 bits */
    INITIALOFFSET + 0x12c5f92c, /*  2 chars,  22 bits */
    INITIALOFFSET + 0x1c28f5c3, /*  3 chars,  33 bits */
    INITIALOFFSET + 0x258bf259, /*  4 chars,  44 bits */
    INITIALOFFSET + 0x2eeeeeef, /*  5 chars,  55 bits */
    INITIALOFFSET + 0x3851eb85, /*  6 chars,  66 bits */
    INITIALOFFSET + 0x41b4e81b, /*  7 chars,  77 bits */
    INITIALOFFSET + 0x4b17e4b1, /*  8 chars,  88 bits */
    INITIALOFFSET + 0x547ae148, /*  9 chars,  99 bits */
    INITIALOFFSET + 0x5dddddde, /* 10 chars, 110 bits */
    INITIALOFFSET + 0x6740da74, /* 11 chars, 121 bits */
    INITIALOFFSET + 0x70a3d70a, /* 12 chars, 132 bits */
    INITIALOFFSET + 0x7a06d3a0, /* 13 chars, 143 bits */
    INITIALOFFSET + 0x8369d037, /* 14 chars, 154 bits */
    INITIALOFFSET + 0x8ccccccd, /* 15 chars, 165 bits */
    INITIALOFFSET + 0x962fc963  /* 16 chars, 176 bits */
#else
    /* Offsets computed with a small rounding error... */
    0,
    INITIALOFFSET +  1 * CHARTIME,
    INITIALOFFSET +  2 * CHARTIME,
    INITIALOFFSET +  3 * CHARTIME,
    INITIALOFFSET +  4 * CHARTIME,
    INITIALOFFSET +  5 * CHARTIME,
    INITIALOFFSET +  6 * CHARTIME,
    INITIALOFFSET +  7 * CHARTIME,
    INITIALOFFSET +  8 * CHARTIME,
    INITIALOFFSET +  9 * CHARTIME,
    INITIALOFFSET + 10 * CHARTIME,
    INITIALOFFSET + 11 * CHARTIME,
    INITIALOFFSET + 12 * CHARTIME,
    INITIALOFFSET + 13 * CHARTIME,
    INITIALOFFSET + 14 * CHARTIME,
    INITIALOFFSET + 15 * CHARTIME,
    INITIALOFFSET + 16 * CHARTIME
#endif
    };

/* Chose filter length dependent on fudge flag 4. */
#define CHOSENSAMPLES(pp) \
    (((pp)->sloppyclockflag & CLK_FLAG4) ? NSAMPLESLONG : NSAMPLES)
/*
Chose how many filter samples to keep.  Several factors are in play.

 1) Discard at least one sample to allow a spike value to be
    discarded.

 2) Discard about 1-in-8 to 1-in-30 samples to handle spikes.

 3) Keep an odd number of samples to avoid median value being biased
    high or low.
*/
#define NKEEP(pp) ((CHOSENSAMPLES(pp) - 1 - (CHOSENSAMPLES(pp)>>3)) | 1)

#define DEFAULT_RESYNC_TIME  (57*60)    /* Gap between resync attempts (s). */
#define RETRY_RESYNC_TIME    (27*60)    /* Gap to emergency resync attempt. */
#ifdef ARCRON_KEEN
#define INITIAL_RESYNC_DELAY 500        /* Delay before first resync. */
#else
#define INITIAL_RESYNC_DELAY 50         /* Delay before first resync. */
#endif

    static const int moff[12] =
        { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };
/* Flags for a raw open() of the clock serial device. */
#ifdef O_NOCTTY /* Good, we can avoid tty becoming controlling tty. */
#define OPEN_FLAGS (O_RDWR | O_NOCTTY)
#else           /* Oh well, it may not matter... */
#define OPEN_FLAGS (O_RDWR)
#endif


/*
 * Imported from ntp_timer module
 */
extern u_long current_time;             /* Current time (s). */
extern struct event timerqueue[];       /* Timer queue. */

/*
 * Imported from ntpd module
 */
extern int debug;                       /* Global debug flag. */

/* Length of queue of command bytes to be sent. */
#define CMDQUEUELEN 4                   /* Enough for two cmds + each \r. */
/* Queue tick time; interval in seconds between chars taken off queue. */
/* Must be >= 2 to allow o\r response to come back uninterrupted. */
#define QUEUETICK   2                   /* Allow o\r reply to finish. */

/*
 * ARC unit control structure
 */
struct arcunit {
    l_fp lastrec;       /* Time tag for the receive time (system). */
    int status;         /* Clock status. */

    int quality;        /* Quality of reception 0--5 for unit. */
                        /* We may also use the values -1 or 6 internally. */

    u_long next_resync; /* Next resync time (s) compared to current_time. */
    int resyncing;      /* Resync in progress if true. */

    /* In the outgoing queue, cmdqueue[0] is next to be sent. */
    char cmdqueue[CMDQUEUELEN+1]; /* Queue of outgoing commands + \0. */

    struct event ev;    /* Event tick for sending chars. */

    u_long saved_flags; /* Saved fudge flags. */
};
#ifdef ARCRON_LEAPSECOND_KEEN
    /* The flag `possible_leap' is set non-zero when any MSF unit
       thinks a leap-second may have happened.

       Set whenever we receive a valid time sample in the first hour of
       the first day of the first/seventh months.

       Outside the special hour this value is unconditionally set
       to zero by the receive routine.

       On finding itself in this timeslot, as long as the value is
       non-negative, the receive routine sets it to a positive value to
       indicate a resync to MSF should be performed.

       In the poll routine, if this value is positive and we are not
       already resyncing (eg from a sync that started just before
       midnight), start resyncing and set this value negative to
       indicate that a leap-triggered resync has been started.  Having
       set this negative prevents the receive routine setting it
       positive and thus prevents multiple resyncs during the witching
       hour.
     */
    static int possible_leap = 0;       /* No resync required by default. */
#endif

static void dummy_event_handler P((struct peer *));
static void   arc_event_handler P((struct peer *));

#define QUALITY_UNKNOWN     -1 /* Indicates unknown clock quality. */
#define MIN_CLOCK_QUALITY    0 /* Min quality clock will return. */
#define MIN_CLOCK_QUALITY_OK 3 /* Min quality for OK reception. */
#define MAX_CLOCK_QUALITY    5 /* Max quality clock will return. */

/*
 * Function prototypes
 */
static  int     arc_start       P((int, struct peer *));
static  void    arc_shutdown    P((int, struct peer *));
static  void    arc_receive     P((struct recvbuf *));
static  void    arc_poll        P((int, struct peer *));

/*
 * Transfer vector
 */
struct  refclock refclock_arc = {
        arc_start,              /* start up driver */
        arc_shutdown,           /* shut down driver */
        arc_poll,               /* transmit poll message */
        noentry,                /* not used (old arc_control) */
        noentry,                /* initialize driver (not used) */
        noentry,                /* not used (old arc_buginfo) */
        NOFLAGS                 /* not used */
};

/* Queue us up for the next tick. */
#define ENQUEUE(up) \
        do { \
        if((up)->ev.next != 0) { break; } /* WHOOPS! */ \
        (up)->ev.event_time = current_time + QUEUETICK; \
        TIMER_INSERT(timerqueue, &((up)->ev)); \
        } while(0)

/* Placeholder event handler---does nothing safely---soaks up lose tick. */
static void dummy_event_handler(peer)
        struct peer *peer;
{
#ifdef ARCRON_DEBUG
        if(debug) { printf("arc: dummy_event_handler() called.\n"); }
#endif
}

/*
Normal event handler.

Take first character off queue and send to clock if not a null.

Shift characters down and put a null on the end.

We assume that there is no parallelism so no race condition, but even
if there is nothing bad will happen except that we might send some bad
data to the clock once in a while.
*/
static void arc_event_handler(peer)
        struct peer *peer;
{
        struct refclockproc *pp = peer->procptr;
        register struct arcunit *up = (struct arcunit *)pp->unitptr;
        int i;
        char c;
#ifdef ARCRON_DEBUG
        if(debug > 2) { printf("arc: arc_event_handler() called.\n"); }
#endif

        c = up->cmdqueue[0];       /* Next char to be sent. */
        /* Shift down characters, shifting trailing \0 in at end. */
        for(i = 0; i < CMDQUEUELEN; ++i)
            { up->cmdqueue[i] = up->cmdqueue[i+1]; }

        /* Don't send '\0' characters. */
        if(c != '\0') {
            if(write(pp->io.fd, &c, 1) != 1) {
                syslog(LOG_NOTICE, "ARCRON: write to fd %d failed", pp->io.fd);
            }
#ifdef ARCRON_DEBUG
        else if(debug) { printf("arc: sent `%2.2x', fd %d.\n", c, pp->io.fd); }
#endif
        }
        ENQUEUE(up);                    /* Keep ticking... */
}

/*
 * arc_start - open the devices and initialize data for processing
 */
static int
arc_start(unit, peer)
        int unit;
        struct peer *peer;
{
        register struct arcunit *up;
        struct refclockproc *pp;
        int fd;
        char device[20];
#ifdef HAVE_TERMIOS
        struct termios arg;
#endif

        syslog(LOG_NOTICE, "ARCRON: %s: opening unit %d", arc_version, unit);
#ifdef ARCRON_DEBUG
        if(debug) {
            printf("arc: %s: attempt to open unit %d.\n", arc_version, unit);
            }
#endif

        /* Prevent a ridiculous device number causing overflow of device[]. */
        if((unit < 0) || (unit > 255)) { return(0); }

        /*
         * Open serial port. Use CLK line discipline, if available.
         */
        (void)sprintf(device, DEVICE, unit);
#ifdef TTYCLK
#ifdef ARCRON_DEBUG
        if(debug) { printf("arc: unit %d using refclock_open().\n", unit); }
#endif
        if (!(fd = refclock_open(device, SPEED, LDISC_CLK))) {
#ifdef DEBUG
            if(debug) { printf("arc: failed [TTYCLK] to open %s.\n", device); }
#endif
            return(0);
        }
#else
#ifdef ARCRON_DEBUG
        if(debug) { printf("arc: unit %d using open().\n", unit); }
#endif
        fd = open(device, OPEN_FLAGS);
        if(fd < 0) {
#ifdef DEBUG
            if(debug) { printf("arc: failed [open()] to open %s.\n", device); }
#endif
            return(0);
        }

        fcntl(fd, F_SETFL, 0); /* clear the descriptor flags */
#ifdef ARCRON_DEBUG
        if(debug)
            { printf("Opened RS232 port with file descriptor %d.\n", fd); }
#endif

#ifdef HAVE_TERMIOS

        arg.c_iflag = IGNBRK | ISTRIP;
        arg.c_oflag = 0;
        arg.c_cflag = B300 | CS8 | CREAD | CLOCAL | CSTOPB;
        arg.c_lflag = 0;
        arg.c_cc[VMIN] = 1;
        arg.c_cc[VTIME] = 0;

        tcsetattr(fd, TCSANOW, &arg);

#else

        syslog(LOG_ERR, "ARCRON: termios not supported in this driver");
        (void)close(fd);

        return 0;

#endif
#endif /* TTYCLK */

        up = (struct arcunit *) emalloc(sizeof(struct arcunit));
        if(!up) { (void) close(fd); return(0); }
        /* Set structure to all zeros... */
        memset((char *)up, 0, sizeof(struct arcunit));
        pp = peer->procptr;
        pp->io.clock_recv = arc_receive;
        pp->io.srcclock = (caddr_t)peer;
        pp->io.datalen = 0;
        pp->io.fd = fd;
        if(!io_addclock(&pp->io)) { (void) close(fd); free(up); return(0); }
        pp->unitptr = (caddr_t)up;

        /*
         * Initialize miscellaneous variables
         */
        peer->precision = PRECISION;
        peer->stratum = 2;              /* Default to stratum 2 not 0. */
        pp->clockdesc = DESCRIPTION;
        memcpy((char *)&pp->refid, REFID, 4);
        /* Spread out resyncs so that they should remain separated. */
        up->next_resync = current_time + INITIAL_RESYNC_DELAY + (67*unit)%1009;

#if 0 /* Not needed because of zeroing of arcunit structure... */
        up->resyncing = 0;              /* Not resyncing yet. */
        up->saved_flags = 0;            /* Default is all flags off. */
        /* Clear send buffer out... */
        {
        int i;
        for(i = CMDQUEUELEN; i >= 0; --i) { up->cmdqueue[i] = '\0'; }
        }
#endif

#ifdef ARCRON_KEEN
        up->quality = QUALITY_UNKNOWN;  /* Trust the clock immediately. */
#else
        up->quality = MIN_CLOCK_QUALITY;/* Don't trust the clock yet. */
#endif
        /* Set up event structure. */
        up->ev.peer = peer;
        up->ev.event_handler = arc_event_handler;
        ENQUEUE(up);                    /* Start ticking. */
        return(1);
}


/*
 * arc_shutdown - shut down the clock
 */
static void
arc_shutdown(unit, peer)
        int unit;
        struct peer *peer;
{
        register struct arcunit *up;
        struct refclockproc *pp;

        pp = peer->procptr;
        up = (struct arcunit *)pp->unitptr;
        up->ev.event_handler = dummy_event_handler;
        TIMER_DEQUEUE(&(up->ev));       /* Stop ticking. */
        io_closeclock(&pp->io);
        free(up);
}

/*
Compute space left in output buffer.
*/
static int space_left(up)
register struct arcunit *up;
{
    int spaceleft;
    /* Compute space left in buffer after any pending output. */
    for(spaceleft = 0; spaceleft < CMDQUEUELEN; ++spaceleft)
        { if(up->cmdqueue[CMDQUEUELEN - 1 - spaceleft] != '\0') { break; } }
    return(spaceleft);
}

/*
Send command by copying into command buffer as far forward as possible,
after any pending output.

Indicate an error by returning 0 if there is not space for the command.
*/
static int
send_slow(up, fd, s)
register struct arcunit *up;
int fd;
char *s;
{
    int sl = strlen(s);
    int spaceleft = space_left(up);
#ifdef ARCRON_DEBUG
    if(debug > 1) { printf("arc: spaceleft = %d.\n", spaceleft); }
#endif
    if(spaceleft < sl) { /* Should not normally happen... */
#ifdef ARCRON_DEBUG
        syslog(LOG_NOTICE, "ARCRON: send-buffer overrun (%d/%d)",
                           sl, spaceleft);
#endif
        return(0);                      /* FAILED! */
    }

    /* Copy in the command to be sent. */
    while(*s) { up->cmdqueue[CMDQUEUELEN - spaceleft--] = *s++; }

    return(1);
}


#ifdef ARCRON_OWN_FILTER
static int arc_refclock_process P((struct refclockproc *, int, int));
static int arc_refclock_sample P((l_fp *, struct refclockproc *, int, int));
static int arc_refclock_cmpl_fp P((const void *, const void *));
#endif

/* Macro indicating action we will take for different quality values. */
#define quality_action(q) \
        (((q) == QUALITY_UNKNOWN) ?         "UNKNOWN, will use clock anyway" : \
            (((q) < MIN_CLOCK_QUALITY_OK) ? "TOO POOR, will not use clock" : \
                                            "OK, will use clock"))

/*
 * arc_receive - receive data from the serial interface
 */
static void
arc_receive(rbufp)
        struct recvbuf *rbufp;
{
        register struct arcunit *up;
        struct refclockproc *pp;
        struct peer *peer;
        l_fp trtmp;
        char c;
        int i, n, wday, month, bst, status;
        int last_offset;

        /*
         * Initialize pointers and read the timecode and timestamp
         */
        peer = (struct peer *)rbufp->recv_srcclock;
        pp = peer->procptr;
        up = (struct arcunit *)pp->unitptr;


        /*
        If the command buffer is empty, and we are resyncing, insert a
        g\r quality request into it to poll for signal quality again.
        */
        if((up->resyncing) && (space_left(up) == CMDQUEUELEN)) {
#ifdef DEBUG
            if(debug > 1) { printf("arc: inserting signal-quality poll.\n"); }
#endif
            send_slow(up, pp->io.fd, "g\r");
        }

        /*
        The `last_offset' is the offset in lastcode[] of the last byte
        received, and which we assume actually received the input
        timestamp.

        (When we get round to using tty_clk and it is available, we
        assume that we will receive the whole timecode with the
        trailing \r, and that that \r will be timestamped.  But this
        assumption also works if receive the characters one-by-one.)
        */
        last_offset = pp->lencode+rbufp->recv_length - 1;

        /*
        We catch a timestamp iff:

          * The command code is `o' for a timestamp.

          * If ARCRON_MULTIPLE_SAMPLES is undefined then we must have
            exactly char in the buffer (the command code) so that we
            only sample the first character of the timecode as our
            `on-time' character.

          * The first character in the buffer is not the echoed `\r'
            from the `o` command (so if we are to timestamp an `\r' it
            must not be first in the receive buffer with lencode==1.
            (Even if we had other characters following it, we probably
            would have a premature timestamp on the '\r'.)

          * We have received at least one character (I cannot imagine
            how it could be otherwise, but anyway...).
        */
        c = rbufp->recv_buffer[0];
        if((pp->a_lastcode[0] == 'o') &&
#ifndef ARCRON_MULTIPLE_SAMPLES
           (pp->lencode == 1) &&
#endif
           ((pp->lencode != 1) || (c != '\r')) &&
           (last_offset >= 1)) {
            /* Note that the timestamp should be corrected if >1 char rcvd. */
            l_fp timestamp;
            timestamp = rbufp->recv_time;
#ifdef DEBUG
            if(debug) { /* Show \r as `R', other non-printing char as `?'. */
                printf("arc: stamp -->%c<-- (%d chars rcvd)\n",
                       ((c == '\r') ? 'R' : (isgraph(c) ? c : '?')),
                       rbufp->recv_length);
#endif
            }

            /*
            Now correct timestamp by offset of last byte received---we
            subtract from the receive time the delay implied by the
            extra characters received.

            Reject the input if the resulting code is too long, but
            allow for the trailing \r, normally not used but a good
            handle for tty_clk or somesuch kernel timestamper.
            */
            if(last_offset > LENARC) {
#ifdef ARCRON_DEBUG
                if(debug) {
                    printf("arc: input code too long (%d cf %d); rejected.\n",
                           last_offset, LENARC);
                }
#endif
                pp->lencode = 0;
                refclock_report(peer, CEVNT_BADREPLY);
                return;
            }

            L_SUBUF(&timestamp, charoffsets[last_offset]);
#ifdef ARCRON_DEBUG
            if(debug > 1) {
                printf(
"arc: %s%d char(s) rcvd, the last for lastcode[%d]; -%sms offset applied.\n",
                        ((rbufp->recv_length > 1) ? "*** " : ""),
                        rbufp->recv_length,
                        last_offset,
                        mfptoms((unsigned long)0,
                                charoffsets[last_offset],
                                1));
            }
#endif

#ifdef ARCRON_MULTIPLE_SAMPLES
            /*
            If taking multiple samples, capture the current adjusted
            sample iff:

              * No timestamp has yet been captured (it is zero), OR

              * This adjusted timestamp is earlier than the one already
                captured, on the grounds that this one suffered less
                delay in being delivered to us and is more accurate.

            */
            if(L_ISZERO(&(up->lastrec)) ||
               L_ISGEQ(&(up->lastrec), &timestamp))
#endif
                {
#ifdef ARCRON_DEBUG
                if(debug > 1) {
                    printf("arc: system timestamp captured.\n");
#ifdef ARCRON_MULTIPLE_SAMPLES
                    if(!L_ISZERO(&(up->lastrec))) {
                        l_fp diff;
                        diff = up->lastrec;
                        L_SUB(&diff, &timestamp);
                        printf("arc: adjusted timestamp by -%sms.\n",
                               mfptoms(diff.l_i, diff.l_f, 3));
                        }
#endif
                }
#endif
                up->lastrec = timestamp;
            }

        }

        /* Just in case we still have lots of rubbish in the buffer... */
        /* ...and to avoid the same timestamp being reused by mistake, */
        /* eg on receipt of the \r coming in on its own after the      */
        /* timecode.                                                   */
        if(pp->lencode >= LENARC) {
#ifdef ARCRON_DEBUG
            if(debug && (rbufp->recv_buffer[0] != '\r'))
                { printf("arc: rubbish in pp->a_lastcode[].\n"); }
#endif
            pp->lencode = 0;
            return;
        }

        /* Append input to code buffer, avoiding overflow. */
        for(i = 0; i < rbufp->recv_length; i++) {
            if(pp->lencode >= LENARC) { break; } /* Avoid overflow... */
            c = rbufp->recv_buffer[i];

            /* Drop trailing '\r's and drop `h' command echo totally. */
            if(c != '\r' && c != 'h') { pp->a_lastcode[pp->lencode++] = c; }

            /*
            If we've just put an `o' in the lastcode[0], clear the
            timestamp in anticipation of a timecode arriving soon.

            We would expect to get to process this before any of the
            timecode arrives.
            */
            if((c == 'o') && (pp->lencode == 1)) {
                L_CLR(&(up->lastrec));
#ifdef ARCRON_DEBUG
                if(debug > 1) { printf("arc: clearing timestamp.\n"); }
#endif
            }
        }

        /* Handle a quality message. */
        if(pp->a_lastcode[0] == 'g') {
            int r, q;

            if(pp->lencode < 3) { return; } /* Need more data... */
            r = (pp->a_lastcode[1] & 0x7f); /* Strip parity. */
            q = (pp->a_lastcode[2] & 0x7f); /* Strip parity. */
            if(((q & 0x70) != 0x30) || ((q & 0xf) > MAX_CLOCK_QUALITY) ||
               ((r & 0x70) != 0x30)) {
                /* Badly formatted response. */
#ifdef ARCRON_DEBUG
                if(debug) { printf("arc: bad `g' response %2x %2x.\n", r, q); }
#endif
                return;
            }
            if(r == '3') { /* Only use quality value whilst sync in progress. */
                up->quality = (q & 0xf);
#ifdef DEBUG
                if(debug) { printf("arc: signal quality %d.\n", up->quality); }
#endif
            } else if( /* (r == '2') && */ up->resyncing) {
#ifdef DEBUG
                if(debug)
                    {
                    printf("arc: sync finished, signal quality %d: %s\n",
                       up->quality,
                       quality_action(up->quality));
                    }
#endif
                syslog(LOG_NOTICE,
                       "ARCRON: sync finished, signal quality %d: %s",
                       up->quality,
                       quality_action(up->quality));
                up->resyncing = 0; /* Resync is over. */

#ifdef ARCRON_KEEN
                /* Clock quality dubious; resync earlier than usual. */
                if((up->quality == QUALITY_UNKNOWN) ||
                   (up->quality < MIN_CLOCK_QUALITY_OK))
                    { up->next_resync = current_time + RETRY_RESYNC_TIME; }
#endif
            }
            pp->lencode = 0;
            return;
        }

        /* Stop now if this is not a timecode message. */
        if(pp->a_lastcode[0] != 'o') {
            pp->lencode = 0;
            refclock_report(peer, CEVNT_BADREPLY);
            return;
        }

        /* If we don't have enough data, wait for more... */
        if(pp->lencode < LENARC) { return; }


        /* WE HAVE NOW COLLECTED ONE TIMESTAMP (phew)... */
#ifdef ARCRON_DEBUG
        if(debug > 1) { printf("arc: NOW HAVE TIMESTAMP...\n"); }
#endif

        /* But check that we actually captured a system timestamp on it. */
        if(L_ISZERO(&(up->lastrec))) {
#ifdef ARCRON_DEBUG
            if(debug) { printf("arc: FAILED TO GET SYSTEM TIMESTAMP\n"); }
#endif
            pp->lencode = 0;
            refclock_report(peer, CEVNT_BADREPLY);
            return;
        }
        /*
        Append a mark of the clock's received signal quality for the
        benefit of Derek Mulcahy's Tcl/Tk utility (we map the `unknown'
        quality value to `6' for his s/w) and terminate the string for
        sure.  This should not go off the buffer end.
        */
        pp->a_lastcode[pp->lencode] = ((up->quality == QUALITY_UNKNOWN) ?
                                                '6' : ('0' + up->quality));
        pp->a_lastcode[pp->lencode + 1] = '\0'; /* Terminate for printf(). */
        record_clock_stats(&peer->srcadr, pp->a_lastcode);

        /* We don't use the micro-/milli- second part... */
        pp->usec = 0;
        pp->msec = 0;

        n = sscanf(pp->a_lastcode, "o%2d%2d%2d%1d%2d%2d%2d%1d%1d",
            &pp->hour, &pp->minute, &pp->second,
            &wday, &pp->day, &month, &pp->year, &bst, &status);

        /* Validate format and numbers. */
        if(n != 9) {
#ifdef ARCRON_DEBUG
            /* Would expect to have caught major problems already... */
            if(debug) { printf("arc: badly formatted data.\n"); }
#endif
            refclock_report(peer, CEVNT_BADREPLY);
            return;
        }
        /*
        Validate received values at least enough to prevent internal
        array-bounds problems, etc.
        */
        if((pp->hour < 0) || (pp->hour > 23) ||
           (pp->minute < 0) || (pp->minute > 59) ||
           (pp->second < 0) || (pp->second > 60) /*Allow for leap seconds.*/ ||
           (wday < 1) || (wday > 7) ||
           (pp->day < 1) || (pp->day > 31) ||
           (month < 1) || (month > 12) ||
           (pp->year < 0) || (pp->year > 99)) {
            /* Data out of range. */
            refclock_report(peer, CEVNT_BADREPLY);
            return;
        }
        /* Check that BST/UTC bits are the complement of one another. */
        if(!(bst & 2) == !(bst & 4)) {
            refclock_report(peer, CEVNT_BADREPLY);
            return;
        }

        if(status & 0x8) { syslog(LOG_NOTICE, "ARCRON: battery low"); }

        /* Year-2000 alert! */
        /* Attempt to wrap 2-digit date into sensible window. */
        /* This code was written in 1997, so that is the window start. */
        if(pp->year < 97) { pp->year += 2000; }
        else /* if(pp->year < 100) */ { pp->year += 1900; }
        /*
        Attempt to do the right thing by screaming that the code will
        soon break when we get to the end of its useful life.  What a
        hero I am...  PLEASE FIX LEAP-YEAR AND WRAP CODE IN 209X!
        */
        if(pp->year >= 2090) {          /* This should get attention B^> */
            syslog(LOG_NOTICE,
"ARCRON: fix me!  EITHER YOUR DATE IS BADLY WRONG or else I will break soon!");
        }
#ifdef DEBUG
        if(debug) {
            printf("arc: n=%d %02d:%02d:%02d %02d/%02d/%04d %1d %1d\n",
                n,
                pp->hour, pp->minute, pp->second,
                pp->day, month, pp->year, bst, status);
        }
#endif

        /*
        The status value tested for is not strictly supported by the
        clock spec since the value of bit 2 (0x4) is claimed to be
        undefined for MSF, yet does seem to indicate if the last resync
        was successful or not.
        */
        pp->leap = LEAP_NOWARNING;
        status &= 0x7;
        if(status == 0x3) {
            pp->lasttime = current_time;
            if(status != up->status)
                { syslog(LOG_NOTICE, "ARCRON: signal acquired"); }
        } else {
            if(status != up->status) {
                syslog(LOG_NOTICE, "ARCRON: signal lost");
                pp->leap = LEAP_NOTINSYNC; /* MSF clock is free-running. */
                up->status = status;
                refclock_report(peer, CEVNT_FAULT);
                return;
            }
        }
        up->status = status;

        pp->day += moff[month - 1];

        /* Good 'til 1st March 2100 */
        if(((pp->year % 4) == 0) && month > 2) { pp->day++; }

        /* Convert to UTC if required */
        if(bst & 2) {
            pp->hour--;
            if (pp->hour < 0) {
                pp->hour = 23;
                pp->day--;
                /* If we try to wrap round the year (BST on 1st Jan), reject.*/
                if(pp->day < 0) {
                    refclock_report(peer, CEVNT_BADTIME);
                    return;
                }
            }
        }

        /* If clock signal quality is unknown, revert to default PRECISION...*/
        if(up->quality == QUALITY_UNKNOWN) { peer->precision = PRECISION; }
        /* ...else improve precision if flag3 is set... */
        else {
            peer->precision = ((pp->sloppyclockflag & CLK_FLAG3) ?
                        HIGHPRECISION : PRECISION);
        }

        /* Notice and log any change (eg from initial defaults) for flags. */
        if(up->saved_flags != pp->sloppyclockflag) {
#ifdef ARCRON_DEBUG
            syslog(LOG_NOTICE, "ARCRON: flags enabled: %s%s%s%s",
                    ((pp->sloppyclockflag & CLK_FLAG1) ? "1" : "."),
                    ((pp->sloppyclockflag & CLK_FLAG2) ? "2" : "."),
                    ((pp->sloppyclockflag & CLK_FLAG3) ? "3" : "."),
                    ((pp->sloppyclockflag & CLK_FLAG4) ? "4" : "."));
            /* Note effects of flags changing... */
            if(debug) {
                printf("arc: CHOSENSAMPLES(pp) = %d.\n", CHOSENSAMPLES(pp));
                printf("arc: NKEEP(pp) = %d.\n", NKEEP(pp));
                printf("arc: PRECISION = %d.\n", peer->precision);
            }
#endif
            up->saved_flags = pp->sloppyclockflag;
        }

        /* Note time of last believable timestamp. */
        pp->lastrec = up->lastrec;

#ifdef ARCRON_LEAPSECOND_KEEN
        /* Find out if a leap-second might just have happened...
           (ie is this the first hour of the first day of Jan or Jul?)
         */
        if((pp->hour == 0) &&
           (pp->day == 1) &&
           ((month == 1) || (month == 7))) {
            if(possible_leap >= 0) {
                /* A leap may have happened, and no resync has started yet...*/
                possible_leap = 1;
                }
        } else {
            /* Definitely not leap-second territory... */
            possible_leap = 0;
        }
#endif

        /*
         * Process the new sample in the median filter and determine the
         * reference clock offset and dispersion. We use lastrec as both
         * the reference time and receive time in order to avoid being
         * cute, like setting the reference time later than the receive
         * time, which may cause a paranoid protocol module to chuck out
         * the data.
         */
#ifdef ARCRON_OWN_FILTER
        if(!arc_refclock_process(pp, CHOSENSAMPLES(pp), NKEEP(pp)))
#else
        if(!refclock_process(pp, CHOSENSAMPLES(pp), NKEEP(pp)))
#endif
            {
            refclock_report(peer, CEVNT_BADTIME);
            if(debug) { printf("arc: sample rejected.\n"); }
            return;
            }
        trtmp = pp->lastrec;
        refclock_receive(peer, &pp->offset, 0, pp->dispersion,
            &trtmp, &pp->lastrec, pp->leap);
}


/* request_time() sends a time request to the clock with given peer. */
/* This automatically reports a fault if necessary. */
/* No data should be sent after this until arc_poll() returns. */
static  void    request_time    P((int, struct peer *));
static void
request_time(unit, peer)
        int unit;
        struct peer *peer;
{
        struct refclockproc *pp = peer->procptr;
        register struct arcunit *up = (struct arcunit *)pp->unitptr;
#ifdef DEBUG
        if(debug) { printf("arc: unit %d: requesting time.\n", unit); }
#endif
        if (!send_slow(up, pp->io.fd, "o\r")) {
#ifdef ARCRON_DEBUG
            syslog(LOG_NOTICE, "ARCRON: unit %d: problem sending", unit);
#endif
            refclock_report(peer, CEVNT_FAULT);
            return;
        }
        pp->polls++;
}

/*
 * arc_poll - called by the transmit procedure
 */
static void
arc_poll(unit, peer)
        int unit;
        struct peer *peer;
{
        register struct arcunit *up;
        struct refclockproc *pp;
        int resync_needed;              /* Should we start a resync? */

        pp = peer->procptr;
        up = (struct arcunit *)pp->unitptr;
        pp->lencode = 0;
        memset(pp->a_lastcode, 0, sizeof(pp->a_lastcode));

#if 0
        /* Flush input. */
        tcflush(pp->io.fd, TCIFLUSH);
#endif

        /* Resync if our next scheduled resync time is here or has passed. */
        resync_needed = (up->next_resync <= current_time);

#ifdef ARCRON_LEAPSECOND_KEEN
        /*
         Try to catch a potential leap-second insertion or deletion quickly.

         In addition to the normal NTP fun of clocks that don't report
         leap-seconds spooking their hosts, this clock does not even
         sample the radio sugnal the whole time, so may miss a
         leap-second insertion or deletion for up to a whole sample
         time.

         To try to minimise this effect, if in the first few minutes of
         the day immediately following a leap-second-insertion point
         (ie in the first hour of the first day of the first and sixth
         months), and if the last resync was in the previous day, and a
         resync is not already in progress, resync the clock
         immediately.

         */
        if((possible_leap > 0) &&       /* Must be 00:XX 01/0{1,7}/XXXX. */
           (!up->resyncing)) {          /* No resync in progress yet. */
           resync_needed = 1;
           possible_leap = -1;          /* Prevent multiple resyncs. */
           syslog(LOG_NOTICE,"ARCRON: unit %d: checking for leap second",unit);
           }
#endif

        /* Do a resync if required... */
        if(resync_needed) {
            /* First, reset quality value to `unknown' so we can detect */
            /* when a quality message has been responded to by this     */
            /* being set to some other value.                           */
            up->quality = QUALITY_UNKNOWN;

            /* Note that we are resyncing... */
            up->resyncing = 1;

            /* Now actually send the resync command and an immediate poll. */
#ifdef DEBUG
            if(debug) { printf("arc: sending resync command (h\\r).\n"); }
#endif
            syslog(LOG_NOTICE, "ARCRON: unit %d: sending resync command", unit);
            send_slow(up, pp->io.fd, "h\r");

            /* Schedule our next resync... */
            up->next_resync = current_time + DEFAULT_RESYNC_TIME;

            /* Drop through to request time if appropriate. */
        }

        /* If clock quality is too poor to trust, indicate a fault. */
        /* If quality is QUALITY_UNKNOWN and ARCRON_KEEN is defined,*/
        /* we'll cross our fingers and just hope that the thing     */
        /* synced so quickly we did not catch it---we'll            */
        /* double-check the clock is OK elsewhere.                  */
        if(
#ifdef ARCRON_KEEN
           (up->quality != QUALITY_UNKNOWN) &&
#else
           (up->quality == QUALITY_UNKNOWN) ||
#endif
           (up->quality < MIN_CLOCK_QUALITY_OK)) {
#ifdef DEBUG
            if(debug) {
                printf("arc: clock quality %d too poor.\n", up->quality);
            }
#endif
            refclock_report(peer, CEVNT_FAULT);
            return;
        }
        /* This is the normal case: request a timestamp. */
        request_time(unit, peer);
}





#ifdef ARCRON_OWN_FILTER

/* Very small fixes to the 3-5.90 ntp_refclock.c code. */

#include "ntp_unixtime.h" /* For TVUTOTSF, etc. */
#define REFCLOCKMAXDISPERSE (FP_SECOND/4) /* max sample dispersion */

/*
 * Compare two l_fp's - used with qsort()
 */
static int
arc_refclock_cmpl_fp(p1, p2)
        register const void *p1, *p2;   /* l_fp to compare */
{

        if (!L_ISGEQ((l_fp *)p1, (l_fp *)p2))
                return (-1);
        if (L_ISEQU((l_fp *)p1, (l_fp *)p2))
                return (0);
        return (1);
}

/*
 * refclock_process - process a pile of samples from the clock
 *
 * This routine converts the timecode in the form days, hours, minutes,
 * seconds, milliseconds/microseconds to internal timestamp format.
 * Further processing is then delegated to refclock sample
 */
static int
arc_refclock_process(pp, nstart, nskeep)
        struct refclockproc *pp; /* peer structure pointer */
        int nstart;             /* stages of median filter */
        int nskeep;             /* stages after outlyer trim */
{
        l_fp offset;

        /*
         * Compute the timecode timestamp from the days, hours, minutes,
         * seconds and milliseconds/microseconds of the timecode. Use
         * clocktime() for the aggregate seconds and the msec/usec for
         * the fraction, when present. Note that this code relies on the
         * filesystem time for the years and does not use the years of
         * the timecode.
         */
        if (!clocktime(pp->day, pp->hour, pp->minute, pp->second, GMT,
            pp->lastrec.l_ui, &pp->yearstart, &offset.l_ui))
                return (0);
        if (pp->usec) {
                TVUTOTSF(pp->usec, offset.l_uf);
        } else {
                MSUTOTSF(pp->msec, offset.l_uf);
        }

        L_ADD(&offset, &pp->fudgetime1);

        pp->lastref = offset;   /* save last reference time */

        /*
         * Include the configured fudgetime1 adjustment.
         */
        L_SUB(&offset, &pp->lastrec); /* form true offset */
#ifdef ARCRON_DEBUG
        if(debug > 1) { /* DHD addition. */
            printf("arc: raw offset %sms.\n",
                mfptoms(offset.l_i, offset.l_f, 2));
        }
#endif

        return arc_refclock_sample(&offset, pp, nstart, nskeep);
}

/*
 * refclock_sample - process a pile of samples from the clock
 *
 * This routine converts the timecode in the form days, hours, miinutes,
 * seconds, milliseconds/microseconds to internal timestamp format. It
 * then calculates the difference from the receive timestamp and
 * assembles the samples in a shift register. It implements a recursive
 * median filter to suppress spikes in the data, as well as determine a
 * rough dispersion estimate. A configuration constant time adjustment
 * fudgetime1 can be added to the final offset to compensate for various
 * systematic errors. The routine returns one if success and zero if
 * failure due to invalid timecode data or very noisy offsets.
 *
 * This interface is needed to allow for clocks (e. g. parse) that can
 * provide the correct offset including year information (though NTP
 * usually gives up on offsets greater than 1000 seconds).
 */
static int
arc_refclock_sample(sample_offset, pp, nstart, nskeep)
        l_fp *sample_offset;    /* input offset (offset! - not a time stamp)
                                   for filter machine */
        struct refclockproc *pp; /* peer structure pointer */
        int nstart;             /* stages of median filter */
        int nskeep;             /* stages after outlyer trim */
{
        int i, n;
        l_fp offset, median, lftmp;
        l_fp off[MAXSTAGE];
        u_fp disp;

        /*
         * Subtract the receive timestamp from the timecode timestamp
         * to form the raw offset. Insert in the median filter shift
         * register.
         */
        pp->nstages = nstart;
        offset = *sample_offset;

        i = ((int)(pp->coderecv)) % pp->nstages;

        pp->filter[i] = offset;
        if (pp->coderecv == 0)
                for (i = 1; (u_int) i < pp->nstages; i++)
                        pp->filter[i] = pp->filter[0];
        pp->coderecv++;

        /*
         * Copy the raw offsets and sort into ascending order
         */
        for (i = 0; (u_int) i < pp->nstages; i++)
                off[i] = pp->filter[i];
        qsort((char *)off, pp->nstages, sizeof(l_fp), arc_refclock_cmpl_fp);

        /*
         * Reject the furthest from the median of nstages samples until
         * nskeep samples remain.
         */
        i = 0;
        n = pp->nstages;
        while ((n - i) > nskeep) {
                lftmp = off[n - 1];
                median = off[(n + i) / 2];
                L_SUB(&lftmp, &median);
                L_SUB(&median, &off[i]);
                if (L_ISHIS(&median, &lftmp)) {
                        /* reject low end */
                        i++;
                } else {
                        /* reject high end */
                        n--;
                }
        }

        /*
         * Compute the dispersion based on the difference between the
         * extremes of the remaining offsets. Add to this the time since
         * the last clock update, which represents the dispersion
         * increase with time. We know that NTP_MAXSKEW is 16. If the
         * sum is greater than the allowed sample dispersion, bail out.
         * If the loop is unlocked, return the most recent offset;
         * otherwise, return the median offset.
         */
        lftmp = off[n - 1];
        L_SUB(&lftmp, &off[i]);
        disp = LFPTOFP(&lftmp) + current_time - pp->lasttime;
        if (disp > REFCLOCKMAXDISPERSE)
                return (0);

        pp->offset = off[(n + i) / 2];   /* Originally: pp->offset = offset; */
        pp->dispersion = disp;

        return (1);
}

#endif /* ARCRON_OWN_FILTER */

#endif
