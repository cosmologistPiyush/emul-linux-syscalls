# csharpcomp.m4 serial 4 (gettext-0.14.2)
dnl Copyright (C) 2003-2005 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

# Prerequisites of csharpcomp.sh.
# Sets HAVE_CSHARPCOMP to nonempty if csharpcomp.sh will work.

AC_DEFUN([gt_CSHARPCOMP],
[
  AC_REQUIRE([gt_CSHARP_CHOICE])
  AC_MSG_CHECKING([for C[#] compiler])
  HAVE_CSHARPCOMP=1
  pushdef([AC_MSG_CHECKING],[:])dnl
  pushdef([AC_CHECKING],[:])dnl
  pushdef([AC_MSG_RESULT],[:])dnl
  AC_CHECK_PROG(HAVE_CSCC_IN_PATH, cscc, yes)
  AC_CHECK_PROG(HAVE_MCS_IN_PATH, mcs, yes)
  AC_CHECK_PROG(HAVE_CSC_IN_PATH, csc, yes)
  popdef([AC_MSG_RESULT])dnl
  popdef([AC_CHECKING])dnl
  popdef([AC_MSG_CHECKING])dnl
  for impl in "$CSHARP_CHOICE" pnet mono sscli no; do
    case "$impl" in
      pnet)
        if test -n "$HAVE_CSCC_IN_PATH" \
           && cscc --version >/dev/null 2>/dev/null; then
          HAVE_CSCC=1
          ac_result="cscc"
          break
        fi
        ;;
      mono)
        if test -n "$HAVE_MCS_IN_PATH" \
           && mcs --version >/dev/null 2>/dev/null; then
          HAVE_MCS=1
          ac_result="mcs"
          break
        fi
        ;;
      sscli)
        if test -n "$HAVE_CSC_IN_PATH" \
           && csc -help >/dev/null 2>/dev/null \
           && { if csc -help 2>/dev/null | grep -i chicken > /dev/null; then false; else true; fi; }; then
          HAVE_CSC=1
          ac_result="csc"
          break
        fi
        ;;
      no)
        HAVE_CSHARPCOMP=
        ac_result="no"
        break
        ;;
    esac
  done
  AC_MSG_RESULT([$ac_result])
  AC_SUBST(HAVE_CSCC)
  AC_SUBST(HAVE_MCS)
  AC_SUBST(HAVE_CSC)
])
