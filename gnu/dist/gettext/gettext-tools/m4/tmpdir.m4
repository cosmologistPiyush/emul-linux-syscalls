# tmpdir.m4 serial 1 (gettext-0.11)
dnl Copyright (C) 2001-2002 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

# Prerequisites for lib/tmpdir.c

AC_DEFUN([gt_TMPDIR],
[
  AC_STAT_MACROS_BROKEN
  AC_CHECK_FUNCS(__secure_getenv)
])
