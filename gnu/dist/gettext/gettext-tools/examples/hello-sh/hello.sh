#!/bin/sh
# Example for use of GNU gettext.
# Copyright (C) 2003 Free Software Foundation, Inc.
# This file is in the public domain.
#
# Source code of the POSIX sh program.

. gettext.sh

TEXTDOMAIN=hello-sh
export TEXTDOMAIN
TEXTDOMAINDIR='@localedir@'
export TEXTDOMAINDIR

gettext "Hello, world!"; echo

pid=$$
eval_gettext "This program is running as process number \$pid."; echo
