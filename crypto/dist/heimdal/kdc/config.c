/*
 * Copyright (c) 1997-2002 Kungliga Tekniska H�gskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 *
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 *
 * 3. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */

#include "kdc_locl.h"
#include <getarg.h>
#include <parse_bytes.h>

__RCSID("$Heimdal: config.c,v 1.43 2002/08/29 01:51:07 assar Exp $"
        "$NetBSD: config.c,v 1.7 2002/09/12 13:19:00 joda Exp $");

static const char *config_file;	/* location of kdc config file */

int require_preauth = -1;	/* 1 == require preauth for all principals */

size_t max_request;		/* maximal size of a request */

static char *max_request_str;	/* `max_request' as a string */

time_t kdc_warn_pwexpire;	/* time before expiration to print a warning */

struct dbinfo *databases;
HDB **db;
int num_db;

const char *port_str;

#ifdef HAVE_DAEMON
int detach_from_console = -1;
#define DETACH_IS_DEFAULT FALSE
#endif

int enable_http = -1;
int no_detach;
krb5_boolean encode_as_rep_as_tgs_rep; /* bug compatibility */

krb5_boolean check_ticket_addresses;
krb5_boolean allow_null_ticket_addresses;
krb5_boolean allow_anonymous;

static struct getarg_strings addresses_str;	/* addresses to listen on */
krb5_addresses explicit_addresses;

#ifdef KRB4
char *v4_realm;
int enable_v4 = -1;
int enable_524 = -1;
int enable_kaserver = -1;
#endif

static int help_flag;
static int version_flag;

static struct getargs args[] = {
    { 
	"config-file",	'c',	arg_string,	&config_file, 
	"location of config file",	"file" 
    },
    { 
	"require-preauth",	'p',	arg_negative_flag, &require_preauth, 
	"don't require pa-data in as-reqs"
    },
    { 
	"max-request",	0,	arg_string, &max_request, 
	"max size for a kdc-request", "size"
    },
#if 0
    {
	"database",	'd', 	arg_string, &databases,
	"location of database", "database"
    },
#endif
    { "enable-http", 'H', arg_flag, &enable_http, "turn on HTTP support" },
    { "no-detach",   'D', arg_flag, &no_detach, "do not detach from tty" },
#ifdef KRB4
    {	"kerberos4",	0, 	arg_negative_flag, &enable_v4,
	"don't respond to kerberos 4 requests" 
    },
    {	"524",		0, 	arg_negative_flag, &enable_524,
	"don't respond to 524 requests" 
    },
    { 
	"v4-realm",	'r',	arg_string, &v4_realm, 
	"realm to serve v4-requests for"
    },
    {
	"kaserver", 'K', arg_flag,   &enable_kaserver,
	"enable kaserver support"
    },
#endif
    {	"ports",	'P', 	arg_string, &port_str,
	"ports to listen to", "portspec"
    },
#ifdef HAVE_DAEMON
#if DETACH_IS_DEFAULT
    {
	"detach",       'D',      arg_negative_flag, &detach_from_console, 
	"don't detach from console"
    },
#else
    {
	"detach",       0 ,      arg_flag, &detach_from_console, 
	"detach from console"
    },
#endif
#endif
    {	"addresses",	0,	arg_strings, &addresses_str,
	"addresses to listen on", "list of addresses" },
    {	"help",		'h',	arg_flag,   &help_flag },
    {	"version",	'v',	arg_flag,   &version_flag }
};

static int num_args = sizeof(args) / sizeof(args[0]);

static void
usage(int ret)
{
    arg_printusage (args, num_args, NULL, "");
    exit (ret);
}

static void
get_dbinfo(void)
{
    const krb5_config_binding *top_binding = NULL;
    const krb5_config_binding *db_binding;
    const krb5_config_binding *default_binding = NULL;
    struct dbinfo *di, **dt;
    const char *default_dbname = HDB_DEFAULT_DB;
    const char *default_mkey = HDB_DB_DIR "/m-key";
    const char *p;

    databases = NULL;
    dt = &databases;
    while((db_binding = (const krb5_config_binding *)
	   krb5_config_get_next(context, NULL, &top_binding, 
				krb5_config_list, 
				"kdc", 
				"database",
				NULL))) {
	p = krb5_config_get_string(context, db_binding, "realm", NULL);
	if(p == NULL) {
	    if(default_binding) {
		krb5_warnx(context, "WARNING: more than one realm-less "
			   "database specification");
		krb5_warnx(context, "WARNING: using the first encountered");
	    } else
		default_binding = db_binding;
	    continue;
	}
	di = calloc(1, sizeof(*di));
	di->realm = strdup(p);
	p = krb5_config_get_string(context, db_binding, "dbname", NULL);
	if(p)
	    di->dbname = strdup(p);
	p = krb5_config_get_string(context, db_binding, "mkey_file", NULL);
	if(p)
	    di->mkey_file = strdup(p);
	*dt = di;
	dt = &di->next;
    }
    if(default_binding) {
	di = calloc(1, sizeof(*di));
	p = krb5_config_get_string(context, default_binding, "dbname", NULL);
	if(p) {
	    di->dbname = strdup(p);
	    default_dbname = p;
	}
	p = krb5_config_get_string(context, default_binding, "mkey_file", NULL);
	if(p) {
	    di->mkey_file = strdup(p);
	    default_mkey = p;
	}
	*dt = di;
	dt = &di->next;
    } else if(databases == NULL) {
	/* if there are none specified, use some default */
	di = calloc(1, sizeof(*di));
	di->dbname = strdup(default_dbname);
	di->mkey_file = strdup(default_mkey);
	*dt = di;
	dt = &di->next;
    }
    for(di = databases; di; di = di->next) {
	if(di->dbname == NULL)
	    di->dbname = strdup(default_dbname);
	if(di->mkey_file == NULL) {
	    p = strrchr(di->dbname, '.');
	    if(p == NULL || strchr(p, '/') != NULL)
		/* final pathname component does not contain a . */
		asprintf(&di->mkey_file, "%s.mkey", di->dbname);
	    else
		/* the filename is something.else, replace .else with
                   .mkey */
		asprintf(&di->mkey_file, "%.*s.mkey", 
			 (int)(p - di->dbname), di->dbname);
	}
    }
}

static void
add_one_address (const char *str, int first)
{
    krb5_error_code ret;
    krb5_addresses tmp;

    ret = krb5_parse_address (context, str, &tmp);
    if (ret)
	krb5_err (context, 1, ret, "parse_address `%s'", str);
    if (first)
	krb5_copy_addresses(context, &tmp, &explicit_addresses);
    else
	krb5_append_addresses(context, &explicit_addresses, &tmp);
    krb5_free_addresses (context, &tmp);
}

void
configure(int argc, char **argv)
{
    int optind = 0;
    int e;
    const char *p;
    
    while((e = getarg(args, num_args, argc, argv, &optind)))
	warnx("error at argument `%s'", argv[optind]);

    if(help_flag)
	usage (0);

    if (version_flag) {
	print_version(NULL);
	exit(0);
    }

    argc -= optind;
    argv += optind;

    if (argc != 0)
	usage(1);
    
    {
	krb5_error_code ret;
	char **files;
	char *tmp;
	if(config_file == NULL)
	    config_file = _PATH_KDC_CONF;
	asprintf(&tmp, "%s:%s", config_file, krb5_config_file);
	if(tmp == NULL)
	    krb5_errx(context, 1, "out of memory");
	    
	krb5_config_file = tmp;

	ret = krb5_get_default_config_files(&files);
	if(ret) 
	    krb5_err(context, 1, ret, "reading configuration files");
	ret = krb5_set_config_files(context, files);
	krb5_free_config_files(files);
	if(ret) 
	    krb5_err(context, 1, ret, "reading configuration files");
    }

    get_dbinfo();
    
    if(max_request_str){
	max_request = parse_bytes(max_request_str, NULL);
    }

    if(max_request == 0){
	p = krb5_config_get_string (context,
				    NULL,
				    "kdc",
				    "max-request",
				    NULL);
	if(p)
	    max_request = parse_bytes(p, NULL);
    }
    
    if(require_preauth == -1)
	require_preauth = krb5_config_get_bool(context, NULL, "kdc", 
					       "require-preauth", NULL);

    if(port_str == NULL){
	p = krb5_config_get_string(context, NULL, "kdc", "ports", NULL);
	if (p != NULL)
	    port_str = strdup(p);
    }

    explicit_addresses.len = 0;

    if (addresses_str.num_strings) {
	int i;

	for (i = 0; i < addresses_str.num_strings; ++i)
	    add_one_address (addresses_str.strings[i], i == 0);
	free_getarg_strings (&addresses_str);
    } else {
	char **foo = krb5_config_get_strings (context, NULL,
					      "kdc", "addresses", NULL);

	if (foo != NULL) {
	    add_one_address (*foo++, TRUE);
	    while (*foo)
		add_one_address (*foo++, FALSE);
	}
    }

#ifdef KRB4
    if(enable_v4 == -1)
	enable_v4 = krb5_config_get_bool_default(context, NULL, TRUE, "kdc", 
					 "enable-kerberos4", NULL);
    if(enable_524 == -1)
	enable_524 = krb5_config_get_bool_default(context, NULL, enable_v4, 
						  "kdc", "enable-524", NULL);
#endif

    if(enable_http == -1)
	enable_http = krb5_config_get_bool(context, NULL, "kdc", 
					   "enable-http", NULL);
    check_ticket_addresses = 
	krb5_config_get_bool_default(context, NULL, TRUE, "kdc", 
				     "check-ticket-addresses", NULL);
    allow_null_ticket_addresses = 
	krb5_config_get_bool_default(context, NULL, TRUE, "kdc", 
				     "allow-null-ticket-addresses", NULL);

    allow_anonymous = 
	krb5_config_get_bool(context, NULL, "kdc", 
			     "allow-anonymous", NULL);
#ifdef KRB4
    if(v4_realm == NULL){
	p = krb5_config_get_string (context, NULL, 
				    "kdc",
				    "v4-realm",
				    NULL);
	if(p)
	    v4_realm = strdup(p);
    }
    if (enable_kaserver == -1)
	enable_kaserver = krb5_config_get_bool_default(context, NULL, FALSE,
						       "kdc",
						       "enable-kaserver",
						       NULL);
#endif

    encode_as_rep_as_tgs_rep = krb5_config_get_bool(context, NULL, "kdc", 
						    "encode_as_rep_as_tgs_rep", 
						    NULL);

    kdc_warn_pwexpire = krb5_config_get_time (context, NULL,
					      "kdc",
					      "kdc_warn_pwexpire",
					      NULL);

#ifdef HAVE_DAEMON
    if(detach_from_console == -1) 
	detach_from_console = krb5_config_get_bool_default(context, NULL, 
							   DETACH_IS_DEFAULT,
							   "kdc",
							   "detach", NULL);
#endif
    kdc_openlog();
    if(max_request == 0)
	max_request = 64 * 1024;
    if(require_preauth == -1)
	require_preauth = 1;
    if (port_str == NULL)
	port_str = "+";
#ifdef KRB4
    if(v4_realm == NULL){
	v4_realm = malloc(40); /* REALM_SZ */
	krb_get_lrealm(v4_realm, 1);
    }
#endif
}
