#!/bin/sh
# Emulate nroff with groff.

prog="$0"
# Default device.
# First try the "locale charmap" command, because it's most reliable.
# On systems where it doesn't exist, look at the environment variables.
# XXX: commented out because /bin/sh doesn't like not finding "locale",
#      and ignores the error redirection in this case.
#case "`locale charmap 2>/dev/null`" in
#  UTF-8)
#    T=-Tutf8 ;;
#  ISO-8859-1)
#    T=-Tlatin1 ;;
#  IBM-1047)
#    T=-Tcp1047 ;;
#  *)
    case "${LC_ALL-${LC_CTYPE-${LANG}}}" in
      *.UTF-8)
        T=-Tutf8 ;;
      iso_8859_1 | *.ISO-8859-1)
        T=-Tlatin1 ;;
      *.IBM-1047)
        T=-Tcp1047 ;;
      *)
        case "$LESSCHARSET" in
          utf-8)
            T=-Tutf8 ;;
          latin1)
            T=-Tlatin1 ;;
          cp1047)
            T=-Tcp1047 ;;
          *)
            T=-Tascii ;;
          esac ;;
#     esac ;;
esac
opts=
safer=-S

# `for i; do' doesn't work with some versions of sh

for i
  do
  case $1 in
    -h)
      opts="$opts -P-h" ;;
    -[eq] | -s*)
      # ignore these options
      ;;
    -[mrnoT])
      echo "$prog: option $1 requires an argument" >&2
      exit 1 ;;
    -i | -[mrno]*)
      opts="$opts $1" ;;
    -Tascii | -Tlatin1 | -Tutf8 | -Tcp1047)
      T=$1 ;;
    -T*)
      # ignore other devices
      ;;
    -S)
      # safer behaviour
      safer=-S ;;
    -U)
      # unsafe behaviour
      safer=-U ;;
    -u*)
      # Solaris 2.2 `man' uses -u0; ignore it,
      # since `less' and `more' can use the emboldening info.
      ;;
    --)
      shift
      break ;;
    -)
      break ;;
    -*)
      echo "$prog: invalid option $1" >&2
      exit 1 ;;
    *)
      break ;;
  esac
  shift
done

# This shell script is intended for use with man, so warnings are
# probably not wanted.  Also load nroff-style character definitions.
exec groff $safer -Wall -mtty-char $T $opts ${1+"$@"}
