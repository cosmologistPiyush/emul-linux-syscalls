# This file is automatically generated.  DO NOT EDIT!
# Generated from: 	NetBSD: mknative-gcc,v 1.7 2003/08/22 00:24:46 mrg Exp 
#
G_F2CEXT=abort derf derfc ef1asc ef1cmc erf erfc exit getarg getenv iargc  signal system flush ftell fseek access besj0 besj1 besjn besy0 besy1  besyn chdir chmod ctime dbesj0 dbesj1 dbesjn dbesy0 dbesy1 dbesyn  dtime etime fdate fgetc fget flush1 fnum fputc fput fstat gerror  getcwd getgid getlog getpid getuid gmtime hostnm idate ierrno irand  isatty itime kill link lnblnk lstat ltime mclock perror rand rename  secnds second sleep srand stat symlnk time ttynam umask unlink  vxttim alarm  date_y2kbuggy date_y2kbug vxtidt_y2kbuggy vxtidt_y2kbug
G_ALL_CFLAGS=-I. -I${GNUHOSTDIST}/libf2c/libF77 -I.. -I${GNUHOSTDIST}/libf2c/libF77/..  -DRETSIGTYPE=void -Donexit=atexit -DSkip_f2c_Undefs=1 -DIEEE_COMPLEX_DIVIDE=1  -O2
G_OBJS=F77_aloc.lo VersionF.lo s_rnge.lo abort_.lo getarg_.lo iargc_.lo getenv_.lo signal_.lo s_stop.lo s_paus.lo system_.lo cabs.lo derf_.lo derfc_.lo erf_.lo erfc_.lo sig_die.lo exit_.lo setarg.lo setsig.lo pow_ci.lo pow_dd.lo pow_di.lo pow_hh.lo pow_ii.lo  pow_ri.lo pow_zi.lo pow_zz.lo  pow_qq.lo c_abs.lo c_cos.lo c_div.lo c_exp.lo c_log.lo c_sin.lo c_sqrt.lo z_abs.lo z_cos.lo z_div.lo z_exp.lo z_log.lo z_sin.lo z_sqrt.lo r_abs.lo r_acos.lo r_asin.lo r_atan.lo r_atn2.lo r_cnjg.lo r_cos.lo r_cosh.lo r_dim.lo r_exp.lo r_imag.lo r_int.lo r_lg10.lo r_log.lo r_mod.lo r_nint.lo r_sign.lo r_sin.lo r_sinh.lo r_sqrt.lo r_tan.lo r_tanh.lo d_abs.lo d_acos.lo d_asin.lo d_atan.lo d_atn2.lo d_cnjg.lo d_cos.lo d_cosh.lo d_dim.lo d_exp.lo d_imag.lo d_int.lo d_lg10.lo d_log.lo d_mod.lo d_nint.lo d_prod.lo d_sign.lo d_sin.lo d_sinh.lo d_sqrt.lo d_tan.lo d_tanh.lo i_abs.lo i_dim.lo i_dnnt.lo i_indx.lo i_len.lo i_mod.lo i_nint.lo i_sign.lo  h_abs.lo h_dim.lo h_dnnt.lo h_indx.lo h_len.lo h_mod.lo  h_nint.lo h_sign.lo l_ge.lo l_gt.lo l_le.lo l_lt.lo hl_ge.lo hl_gt.lo hl_le.lo hl_lt.lo ef1asc_.lo ef1cmc_.lo s_cat.lo s_cmp.lo s_copy.lo lbitbits.lo lbitshft.lo qbitbits.lo qbitshft.lo
G_ALL_CFLAGS+=-I. -I${GNUHOSTDIST}/libf2c/libI77 -I.. -I${GNUHOSTDIST}/libf2c/libI77/..   -DHAVE_CONFIG_H  -O2
G_OBJS+=VersionI.lo backspace.lo close.lo dfe.lo dolio.lo due.lo endfile.lo err.lo  fmt.lo fmtlib.lo iio.lo ilnw.lo inquire.lo lread.lo lwrite.lo open.lo  rdfmt.lo rewind.lo rsfe.lo rsli.lo rsne.lo sfe.lo sue.lo typesize.lo uio.lo  util.lo wref.lo wrtfmt.lo wsfe.lo wsle.lo wsne.lo xwsne.lo  ftell_.lo
G_ALL_CFLAGS+=-I. -I${GNUHOSTDIST}/libf2c/libU77 -I${GNUHOSTDIST}/libf2c/libU77/../libI77 -I..  -I${GNUHOSTDIST}/libf2c/libU77/..  -DHAVE_CONFIG_H  -O2
G_OBJS+=VersionU.lo gerror_.lo perror_.lo ierrno_.lo itime_.lo time_.lo  unlink_.lo fnum_.lo getpid_.lo getuid_.lo getgid_.lo kill_.lo rand_.lo  srand_.lo irand_.lo sleep_.lo idate_.lo ctime_.lo etime_.lo  dtime_.lo  isatty_.lo ltime_.lo fstat_.lo stat_.lo  lstat_.lo access_.lo link_.lo getlog_.lo ttynam_.lo getcwd_.lo symlnk_.lo  vxttime_.lo vxtidate_.lo gmtime_.lo fdate_.lo secnds_.lo  bes.lo dbes.lo  chdir_.lo chmod_.lo lnblnk_.lo hostnm_.lo rename_.lo fgetc_.lo fputc_.lo  umask_.lo sys_clock_.lo date_.lo second_.lo flush1_.lo mclock_.lo  alarm_.lo datetime_.lo
