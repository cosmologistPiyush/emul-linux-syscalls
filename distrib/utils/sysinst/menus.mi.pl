/*	$NetBSD: menus.mi.pl,v 1.20 2003/06/11 21:35:35 dsl Exp $	*/
/*	Based on english version: */
/*	NetBSD: menus.mi.en,v 1.49 2002/04/04 14:26:44 ad Exp 	*/

/*
 * Copyright 1997 Piermont Information Systems Inc.
 * All rights reserved.
 *
 * Written by Philip A. Nelson for Piermont Information Systems Inc.
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
 *      This product includes software developed for the NetBSD Project by
 *      Piermont Information Systems Inc.
 * 4. The name of Piermont Information Systems Inc. may not be used to endorse
 *    or promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PIERMONT INFORMATION SYSTEMS INC. ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL PIERMONT INFORMATION SYSTEMS INC. BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF 
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * Menu system definitions -- machine independent
 *
 * Some menus may be called directly in the code rather than via the 
 * menu system.
 */

menu netbsd, title "System Instalacyjny NetBSD-@@VERSION@@",
    exit, exitstring "Wyjdz z Systemu Instalacyjnego";
	display action  { toplevel(); };
	option "Zainstaluj NetBSD na twardym dysku",
		action { do_install(); };
	option "Zaktualizuj NetBSD na twardym dysku",
		action { do_upgrade(); };
	option "Przeinstaluj albo zainstaluj dodatkowe pakiety",
		action { do_reinstall_sets(); };
	option "Zrestartuj komputer", exit,
		action (endwin) { system("/sbin/reboot -q"); };
	option "Menu Narzedziowe", sub menu utility;

menu utility, title "Narzedzia NetBSD-@@VERSION@@", exit;
	option "Uruchom /bin/sh",
		action (endwin) { system("/bin/sh"); };
/*	option "test", action { run_prog(RUN_DISPLAY, NULL, "/bin/pwd"); }; */
	option "Ustaw strefe czasowa", 
		action {
			set_timezone();
		};
	option "Skonfiguruj siec",
		action {
			extern int network_up;

			network_up = 0;
			config_network();
		};
/*	option "Skonfiguruj dysk"; XXX add later.  */
	option "Funkcje logowania", action { do_logging(); };
	option "Zatrzymaj system", exit,
		action (endwin) { system("/sbin/halt -q"); };

menu yesno, title "tak lub nie?";
	option "Tak", exit, action  {yesno = 1;};
	option "Nie",  exit, action  {yesno = 0;};

menu noyes, title "tak lub nie?";
	option "Nie",  exit, action  {yesno = 0;};
	option "Tak", exit, action  {yesno = 1;};

menu ok, title "Nacisnij enter aby kontynuowac";
	option "ok", exit;

menu layout, title  "Wybierz swoja instalacje";
	option "Standardowa", 	  exit, action { layoutkind = 1; };
	option "Istniejaca", 	  exit, action { layoutkind = 4; };

menu sizechoice, title  "Wybierz specyfikator rozmiaru";
	option "Megabajty", exit, action 
		{ sizemult = MEG / sectorsize;
		  multname = msg_string(MSG_megname);
		};
	option "Cylindry", exit, action 
		{ sizemult = current_cylsize; 
		  multname = msg_string(MSG_cylname);
		};
	option "Sektory", exit, action 
		{ sizemult = 1; 
		  multname = msg_string(MSG_secname);
		};

menu distmedium, title "Wybierz medium";
	display action { msg_display (MSG_distmedium); nodist = 0; };
	option "ftp",  action	{
				  got_dist = get_via_ftp();
			        },
				exit;
	option "nfs",  action	{ 
				  got_dist = get_via_nfs();
			 	}, exit;
	option "cdrom", action  {
				  got_dist = get_via_cdrom();
				}, exit; 
	option "dyskietka", action {
			          got_dist = get_via_floppy(); 
				}, exit;
	option "niezamontowany SP", action {
				  got_dist = get_via_localfs(); 
				}, exit;
	option "lokalny katalog", action {
				   got_dist = get_via_localdir();
				 }, exit;
	option "zadne",  action { nodist = 1; }, exit;

menu distset, title "Wybierz swoja dystrybucje";
	display action { msg_display (MSG_distset); };
	option "Pelna instalacja", exit;
	option "Inna instalacja", exit, action { customise_sets(); };

menu ftpsource, title "Zmien";
	display action
		{ msg_clear();
		  msg_table_add (MSG_ftpsource, ftp_host, ftp_dir, ftp_user,
		     strcmp(ftp_user, "ftp") == 0 ? ftp_pass :
		       strlen(ftp_pass) != 0 ? "** hidden **" : "", ftp_proxy);
		};
	option "Host", action
		{ msg_prompt (MSG_host, ftp_host, ftp_host, 255); };
	option "Katalog", action
		{ msg_prompt (MSG_dir, ftp_dir, ftp_dir, 255); };
	option "Uzytkownik", action
		{ msg_prompt (MSG_user, ftp_user, ftp_user, 255);
			ftp_pass[0] = '\0';
		}; 
	option "Haslo", action
		{ if (strcmp(ftp_user, "ftp") == 0)
			msg_prompt (MSG_email, ftp_pass, ftp_pass, 255);
		  else {
			msg_prompt_noecho (MSG_passwd, "", ftp_pass, 255);
		  }
		};
	option "Proxy", action
		{ msg_prompt (MSG_proxy, ftp_proxy, ftp_proxy, 255);
		  if (strcmp(ftp_proxy, "") == 0)
			unsetenv("ftp_proxy");
		  else
			setenv("ftp_proxy", ftp_proxy, 1);
		};
	option "Sciagnij Dystrybucje", exit;

menu nfssource, title "Zmien";
	display action
		{ msg_display (MSG_nfssource, nfs_host, nfs_dir); };
	option "Host", action
		{ msg_prompt (MSG_host, NULL, nfs_host, 255); };
	option "Katalog", action
		{ msg_prompt (MSG_dir, NULL, nfs_dir, 255); };
	option "Kontynuuj", exit;

menu nfsbadmount, title "Co chcesz zrobic?";
	option "Sprobowac jeszcze raz", exit, sub menu nfssource, action
		{ yesno = 1; ignorerror = 0; };
	option "Poddac sie", exit, action
		{ yesno = 0; ignorerror = 0; };
	option "Zignorowac, kontynuowac", exit, action
		{ yesno = 1; ignorerror = 1; };


menu fdremount, title "Co chcesz zrobic?";
	option "Sprobowac jeszcze raz", exit, action { yesno = 1; };
	option "Przerwac instalacje", exit, action { yesno = 0; };

menu fdok, title "Nacisnij enter aby kontynuowac";
	option "OK", exit, action { yesno = 1; };
	option "Przerwac instalacje", exit, action { yesno = 0; };

menu crypttype, title "Kodowanie hasel";
	option "DES", exit, action { yesno = 1; };
	option "MD5", exit, action { yesno = 2; };
	option "Blowfish 2^7 round", exit, action { yesno = 3; };
	option "nie zmieniaj", exit, action { yesno = 0; };

menu cdromsource, title "Zmien";
	display action
		{ msg_display (MSG_cdromsource, cdrom_dev, cdrom_dir); };
	option "Urzadzenie", action
		{ msg_prompt (MSG_dev, cdrom_dev, cdrom_dev, SSTRSIZE); };
	option "Katalog", action
		{ msg_prompt (MSG_dir, cdrom_dir, cdrom_dir, STRSIZE); };
	option "Kontynuuj", exit;

menu cdrombadmount, title "Co chcesz zrobic?";
	option "Sprobowac jeszcze raz", exit, sub menu cdromsource, action
		{ yesno = 1; ignorerror = 0; };
	option "Poddac sie", exit, action
		{ yesno = 0; ignorerror = 0; };
	option "Zignorowac, kontynuowac", exit, action
		{ yesno = 1; ignorerror = 1; };


menu localfssource, title "Zmien";
	display action
		{ msg_display (MSG_localfssource, localfs_dev, localfs_fs, localfs_dir); };
	option "Urzadzenie", action
		{ msg_prompt (MSG_dev, localfs_dev, localfs_dev, SSTRSIZE); };
	option "SystemPlikow", action
		{ msg_prompt (MSG_filesys, localfs_fs, localfs_fs, STRSIZE); };
	option "Katalog", action
		{ msg_prompt (MSG_dir, localfs_dir, localfs_dir, STRSIZE); };
	option "Kontynuuj", exit;

menu localfsbadmount, title "Co chcesz zrobic?";
	option "Sprobowac jeszcze raz", exit, sub menu localfssource, action
		{ yesno = 1; ignorerror = 0; };
	option "Poddac sie", exit, action
		{ yesno = 0; ignorerror = 0; };
	option "Zignorowac, kontynuowac", exit, action
		{ yesno = 1; ignorerror = 1; };

menu localdirsource, title "Zmien";
	display action
		{ msg_display(MSG_localdir, localfs_dir); };
	option "Katalog", action
		{ msg_prompt (MSG_dir, localfs_dir, localfs_dir, STRSIZE); },
		exit;
	option "Kontynuuj", exit;

menu localdirbad, title "Co chcesz zrobic?";
	option "Zmien sciezke katalogu",  action
		{ yesno = 1;
	          msg_prompt(MSG_localdir, localfs_dir, localfs_dir, STRSIZE);
		}, exit;
	option "Poddac sie", exit, action
		{ yesno = 0; ignorerror = 0; };
	option "Zignorowac, kontynuowac", exit, action
		{ yesno = 1; ignorerror = 1; };

menu namesrv6, title "  Wybierz serwer nazw IPv6";
	option "ns9.iij.ad.jp", exit, action
		{
#ifdef INET6
		  strlcpy(net_namesvr6, "2001:240::1", sizeof(net_namesvr6));
		  yesno = 1;
#else
		  yesno = 0;
#endif
		}; 
	option "ns-wide.wide.ad.jp", exit, action
		{
#ifdef INET6
		  strlcpy(net_namesvr6, "2001:200:0:1::3", sizeof(net_namesvr6));
		  yesno = 1;
#else
		  yesno = 0;
#endif
		}; 
	option "light.imasy.or.jp", exit, action
		{
#ifdef INET6
		  strlcpy(net_namesvr6, "3ffe:505:0:1:2a0:c9ff:fe61:6521",
		      sizeof(net_namesvr6));
		  yesno = 1;
#else
		  yesno = 0;
#endif
		}; 
	option "inny  ", exit, action
		{ yesno = 0; };

menu ip6autoconf, title "Wykonac autokonfiguracje IPv6?";
	option "Tak", exit, action  {yesno = 1;};
	option "Nie",  exit, action  {yesno = 0;};

menu dhcpautoconf, title "Wykonac autkonfiguracje DHCP?";
	option "Tak", exit, action  {yesno = 1;};
	option "Nie",  exit, action  {yesno = 0;};

menu rootsh, title "Root shell"; 	/* XXX translate */
        option "/bin/csh", exit, action {shellpath = "/bin/csh";};
	option "/bin/ksh", exit, action {shellpath = "/bin/ksh";};
	option "/bin/sh",  exit, action {shellpath = "/bin/sh";};
			 
menu extract, title "Select set extraction verbosity";	/* XXX translate */
	option "Progress bar (recommended)", exit, action  { yesno = 1; };
	option "Silent", exit, action  { yesno = 0; };
	option "Verbose file name listing (slow)", exit, action { yesno = 2; };

