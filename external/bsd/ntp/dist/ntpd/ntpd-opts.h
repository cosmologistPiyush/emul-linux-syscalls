/*	$NetBSD: ntpd-opts.h,v 1.2 2009/12/14 00:43:09 christos Exp $	*/

/*  
 *  EDIT THIS FILE WITH CAUTION  (ntpd-opts.h)
 *  
 *  It has been AutoGen-ed  December 10, 2009 at 04:56:47 AM by AutoGen 5.10
 *  From the definitions    ntpd-opts.def
 *  and the template file   options
 *
 * Generated from AutoOpts 33:0:8 templates.
 */

/*
 *  This file was produced by an AutoOpts template.  AutoOpts is a
 *  copyrighted work.  This header file is not encumbered by AutoOpts
 *  licensing, but is provided under the licensing terms chosen by the
 *  ntpd author or copyright holder.  AutoOpts is licensed under
 *  the terms of the LGPL.  The redistributable library (``libopts'') is
 *  licensed under the terms of either the LGPL or, at the users discretion,
 *  the BSD license.  See the AutoOpts and/or libopts sources for details.
 *
 * This source file is copyrighted and licensed under the following terms:
 *
 * ntpd copyright (c) 1970-2009 David L. Mills and/or others - all rights reserved
 *
 * see html/copyright.html
 */
/*
 *  This file contains the programmatic interface to the Automated
 *  Options generated for the ntpd program.
 *  These macros are documented in the AutoGen info file in the
 *  "AutoOpts" chapter.  Please refer to that doc for usage help.
 */
#ifndef AUTOOPTS_NTPD_OPTS_H_GUARD
#define AUTOOPTS_NTPD_OPTS_H_GUARD 1
#include "config.h"
#include <autoopts/options.h>

/*
 *  Ensure that the library used for compiling this generated header is at
 *  least as new as the version current when the header template was released
 *  (not counting patch version increments).  Also ensure that the oldest
 *  tolerable version is at least as old as what was current when the header
 *  template was released.
 */
#define AO_TEMPLATE_VERSION 135168
#if (AO_TEMPLATE_VERSION < OPTIONS_MINIMUM_VERSION) \
 || (AO_TEMPLATE_VERSION > OPTIONS_STRUCT_VERSION)
# error option template version mismatches autoopts/options.h header
  Choke Me.
#endif

/*
 *  Enumeration of each option:
 */
typedef enum {
    INDEX_OPT_IPV4              =  0,
    INDEX_OPT_IPV6              =  1,
    INDEX_OPT_AUTHREQ           =  2,
    INDEX_OPT_AUTHNOREQ         =  3,
    INDEX_OPT_BCASTSYNC         =  4,
    INDEX_OPT_CONFIGFILE        =  5,
    INDEX_OPT_DEBUG_LEVEL       =  6,
    INDEX_OPT_SET_DEBUG_LEVEL   =  7,
    INDEX_OPT_DRIFTFILE         =  8,
    INDEX_OPT_PANICGATE         =  9,
    INDEX_OPT_JAILDIR           = 10,
    INDEX_OPT_INTERFACE         = 11,
    INDEX_OPT_KEYFILE           = 12,
    INDEX_OPT_LOGFILE           = 13,
    INDEX_OPT_NOVIRTUALIPS      = 14,
    INDEX_OPT_MODIFYMMTIMER     = 15,
    INDEX_OPT_NOFORK            = 16,
    INDEX_OPT_NICE              = 17,
    INDEX_OPT_PIDFILE           = 18,
    INDEX_OPT_PRIORITY          = 19,
    INDEX_OPT_QUIT              = 20,
    INDEX_OPT_PROPAGATIONDELAY  = 21,
    INDEX_OPT_SAVECONFIGQUIT    = 22,
    INDEX_OPT_STATSDIR          = 23,
    INDEX_OPT_TRUSTEDKEY        = 24,
    INDEX_OPT_USER              = 25,
    INDEX_OPT_UPDATEINTERVAL    = 26,
    INDEX_OPT_VAR               = 27,
    INDEX_OPT_DVAR              = 28,
    INDEX_OPT_SLEW              = 29,
    INDEX_OPT_USEPCC            = 30,
    INDEX_OPT_PCCFREQ           = 31,
    INDEX_OPT_VERSION           = 32,
    INDEX_OPT_HELP              = 33,
    INDEX_OPT_MORE_HELP         = 34
} teOptIndex;

#define OPTION_CT    35
#define NTPD_VERSION       "4.2.6"
#define NTPD_FULL_VERSION  "ntpd - NTP daemon program - Ver. 4.2.6"

/*
 *  Interface defines for all options.  Replace "n" with the UPPER_CASED
 *  option name (as in the teOptIndex enumeration above).
 *  e.g. HAVE_OPT( IPV4 )
 */
#define         DESC(n) (ntpdOptions.pOptDesc[INDEX_OPT_## n])
#define     HAVE_OPT(n) (! UNUSED_OPT(& DESC(n)))
#define      OPT_ARG(n) (DESC(n).optArg.argString)
#define    STATE_OPT(n) (DESC(n).fOptState & OPTST_SET_MASK)
#define    COUNT_OPT(n) (DESC(n).optOccCt)
#define    ISSEL_OPT(n) (SELECTED_OPT(&DESC(n)))
#define ISUNUSED_OPT(n) (UNUSED_OPT(& DESC(n)))
#define  ENABLED_OPT(n) (! DISABLED_OPT(& DESC(n)))
#define  STACKCT_OPT(n) (((tArgList*)(DESC(n).optCookie))->useCt)
#define STACKLST_OPT(n) (((tArgList*)(DESC(n).optCookie))->apzArgs)
#define    CLEAR_OPT(n) STMTS( \
                DESC(n).fOptState &= OPTST_PERSISTENT_MASK;   \
                if ( (DESC(n).fOptState & OPTST_INITENABLED) == 0) \
                    DESC(n).fOptState |= OPTST_DISABLED; \
                DESC(n).optCookie = NULL )

/*
 *  Make sure there are no #define name conflicts with the option names
 */
#ifndef     NO_OPTION_NAME_WARNINGS
# ifdef    IPV4
#  warning undefining IPV4 due to option name conflict
#  undef   IPV4
# endif
# ifdef    IPV6
#  warning undefining IPV6 due to option name conflict
#  undef   IPV6
# endif
# ifdef    AUTHREQ
#  warning undefining AUTHREQ due to option name conflict
#  undef   AUTHREQ
# endif
# ifdef    AUTHNOREQ
#  warning undefining AUTHNOREQ due to option name conflict
#  undef   AUTHNOREQ
# endif
# ifdef    BCASTSYNC
#  warning undefining BCASTSYNC due to option name conflict
#  undef   BCASTSYNC
# endif
# ifdef    CONFIGFILE
#  warning undefining CONFIGFILE due to option name conflict
#  undef   CONFIGFILE
# endif
# ifdef    DEBUG_LEVEL
#  warning undefining DEBUG_LEVEL due to option name conflict
#  undef   DEBUG_LEVEL
# endif
# ifdef    SET_DEBUG_LEVEL
#  warning undefining SET_DEBUG_LEVEL due to option name conflict
#  undef   SET_DEBUG_LEVEL
# endif
# ifdef    DRIFTFILE
#  warning undefining DRIFTFILE due to option name conflict
#  undef   DRIFTFILE
# endif
# ifdef    PANICGATE
#  warning undefining PANICGATE due to option name conflict
#  undef   PANICGATE
# endif
# ifdef    JAILDIR
#  warning undefining JAILDIR due to option name conflict
#  undef   JAILDIR
# endif
# ifdef    INTERFACE
#  warning undefining INTERFACE due to option name conflict
#  undef   INTERFACE
# endif
# ifdef    KEYFILE
#  warning undefining KEYFILE due to option name conflict
#  undef   KEYFILE
# endif
# ifdef    LOGFILE
#  warning undefining LOGFILE due to option name conflict
#  undef   LOGFILE
# endif
# ifdef    NOVIRTUALIPS
#  warning undefining NOVIRTUALIPS due to option name conflict
#  undef   NOVIRTUALIPS
# endif
# ifdef    MODIFYMMTIMER
#  warning undefining MODIFYMMTIMER due to option name conflict
#  undef   MODIFYMMTIMER
# endif
# ifdef    NOFORK
#  warning undefining NOFORK due to option name conflict
#  undef   NOFORK
# endif
# ifdef    NICE
#  warning undefining NICE due to option name conflict
#  undef   NICE
# endif
# ifdef    PIDFILE
#  warning undefining PIDFILE due to option name conflict
#  undef   PIDFILE
# endif
# ifdef    PRIORITY
#  warning undefining PRIORITY due to option name conflict
#  undef   PRIORITY
# endif
# ifdef    QUIT
#  warning undefining QUIT due to option name conflict
#  undef   QUIT
# endif
# ifdef    PROPAGATIONDELAY
#  warning undefining PROPAGATIONDELAY due to option name conflict
#  undef   PROPAGATIONDELAY
# endif
# ifdef    SAVECONFIGQUIT
#  warning undefining SAVECONFIGQUIT due to option name conflict
#  undef   SAVECONFIGQUIT
# endif
# ifdef    STATSDIR
#  warning undefining STATSDIR due to option name conflict
#  undef   STATSDIR
# endif
# ifdef    TRUSTEDKEY
#  warning undefining TRUSTEDKEY due to option name conflict
#  undef   TRUSTEDKEY
# endif
# ifdef    USER
#  warning undefining USER due to option name conflict
#  undef   USER
# endif
# ifdef    UPDATEINTERVAL
#  warning undefining UPDATEINTERVAL due to option name conflict
#  undef   UPDATEINTERVAL
# endif
# ifdef    VAR
#  warning undefining VAR due to option name conflict
#  undef   VAR
# endif
# ifdef    DVAR
#  warning undefining DVAR due to option name conflict
#  undef   DVAR
# endif

/* Defined in ntpsim.h!
# ifdef    SLEW
#  warning undefining SLEW due to option name conflict
#  undef   SLEW
# endif
*/

# ifdef    USEPCC
#  warning undefining USEPCC due to option name conflict
#  undef   USEPCC
# endif
# ifdef    PCCFREQ
#  warning undefining PCCFREQ due to option name conflict
#  undef   PCCFREQ
# endif
#else  /* NO_OPTION_NAME_WARNINGS */
# undef IPV4
# undef IPV6
# undef AUTHREQ
# undef AUTHNOREQ
# undef BCASTSYNC
# undef CONFIGFILE
# undef DEBUG_LEVEL
# undef SET_DEBUG_LEVEL
# undef DRIFTFILE
# undef PANICGATE
# undef JAILDIR
# undef INTERFACE
# undef KEYFILE
# undef LOGFILE
# undef NOVIRTUALIPS
# undef MODIFYMMTIMER
# undef NOFORK
# undef NICE
# undef PIDFILE
# undef PRIORITY
# undef QUIT
# undef PROPAGATIONDELAY
# undef SAVECONFIGQUIT
# undef STATSDIR
# undef TRUSTEDKEY
# undef USER
# undef UPDATEINTERVAL
# undef VAR
# undef DVAR
# undef SLEW
# undef USEPCC
# undef PCCFREQ
#endif  /*  NO_OPTION_NAME_WARNINGS */

/* * * * * *
 *
 *  Interface defines for specific options.
 */
#define VALUE_OPT_IPV4           '4'
#define VALUE_OPT_IPV6           '6'
#define VALUE_OPT_AUTHREQ        'a'
#define VALUE_OPT_AUTHNOREQ      'A'
#define VALUE_OPT_BCASTSYNC      'b'
#define VALUE_OPT_CONFIGFILE     'c'
#define VALUE_OPT_DEBUG_LEVEL    'd'
#define VALUE_OPT_SET_DEBUG_LEVEL 'D'
#define VALUE_OPT_DRIFTFILE      'f'
#define VALUE_OPT_PANICGATE      'g'
#define VALUE_OPT_JAILDIR        'i'
#define VALUE_OPT_INTERFACE      'I'
#define VALUE_OPT_KEYFILE        'k'
#define VALUE_OPT_LOGFILE        'l'
#define VALUE_OPT_NOVIRTUALIPS   'L'
#define VALUE_OPT_MODIFYMMTIMER  'M'
#define VALUE_OPT_NOFORK         'n'
#define VALUE_OPT_NICE           'N'
#define VALUE_OPT_PIDFILE        'p'
#define VALUE_OPT_PRIORITY       'P'

#define OPT_VALUE_PRIORITY       (DESC(PRIORITY).optArg.argInt)
#define VALUE_OPT_QUIT           'q'
#define VALUE_OPT_PROPAGATIONDELAY 'r'
#define VALUE_OPT_SAVECONFIGQUIT 22
#define VALUE_OPT_STATSDIR       's'
#define VALUE_OPT_TRUSTEDKEY     't'
#define VALUE_OPT_USER           'u'
#define VALUE_OPT_UPDATEINTERVAL 'U'

#define OPT_VALUE_UPDATEINTERVAL (DESC(UPDATEINTERVAL).optArg.argInt)
#define VALUE_OPT_VAR            27
#define VALUE_OPT_DVAR           28
#define VALUE_OPT_SLEW           'x'
#define VALUE_OPT_USEPCC         30
#define VALUE_OPT_PCCFREQ        31
#define VALUE_OPT_HELP          '?'
#define VALUE_OPT_MORE_HELP     '!'
#define VALUE_OPT_VERSION       INDEX_OPT_VERSION
/*
 *  Interface defines not associated with particular options
 */
#define ERRSKIP_OPTERR  STMTS( ntpdOptions.fOptSet &= ~OPTPROC_ERRSTOP )
#define ERRSTOP_OPTERR  STMTS( ntpdOptions.fOptSet |= OPTPROC_ERRSTOP )
#define RESTART_OPT(n)  STMTS( \
                ntpdOptions.curOptIdx = (n); \
                ntpdOptions.pzCurOpt  = NULL )
#define START_OPT       RESTART_OPT(1)
#define USAGE(c)        (*ntpdOptions.pUsageProc)( &ntpdOptions, c )
/* extracted from /usr/local/gnu/share/autogen/opthead.tpl near line 409 */

/* * * * * *
 *
 *  Declare the ntpd option descriptor.
 */
#ifdef  __cplusplus
extern "C" {
#endif

extern tOptions   ntpdOptions;

#if defined(ENABLE_NLS)
# ifndef _
#   include <stdio.h>
    static inline char* aoGetsText( char const* pz ) {
        if (pz == NULL) return NULL;
        return (char*)gettext( pz );
    }
#   define _(s)  aoGetsText(s)
# endif /* _() */

# define OPT_NO_XLAT_CFG_NAMES  STMTS(ntpdOptions.fOptSet |= \
                                    OPTPROC_NXLAT_OPT_CFG;)
# define OPT_NO_XLAT_OPT_NAMES  STMTS(ntpdOptions.fOptSet |= \
                                    OPTPROC_NXLAT_OPT|OPTPROC_NXLAT_OPT_CFG;)

# define OPT_XLAT_CFG_NAMES     STMTS(ntpdOptions.fOptSet &= \
                                  ~(OPTPROC_NXLAT_OPT|OPTPROC_NXLAT_OPT_CFG);)
# define OPT_XLAT_OPT_NAMES     STMTS(ntpdOptions.fOptSet &= \
                                  ~OPTPROC_NXLAT_OPT;)

#else   /* ENABLE_NLS */
# define OPT_NO_XLAT_CFG_NAMES
# define OPT_NO_XLAT_OPT_NAMES

# define OPT_XLAT_CFG_NAMES
# define OPT_XLAT_OPT_NAMES

# ifndef _
#   define _(_s)  _s
# endif
#endif  /* ENABLE_NLS */

#ifdef  __cplusplus
}
#endif
#endif /* AUTOOPTS_NTPD_OPTS_H_GUARD */
/* ntpd-opts.h ends here */
