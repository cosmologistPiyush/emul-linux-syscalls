/* testavl.c - Test Tim Howes AVL code */
/* $OpenLDAP: pkg/ldap/libraries/liblutil/testtavl.c,v 1.2.2.3 2008/02/11 23:26:42 kurt Exp $ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* Portions Copyright (c) 1993 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */
/* ACKNOWLEDGEMENTS:
 * This work was originally developed by the University of Michigan
 * (as part of U-MICH LDAP). Additional contributors include
 *   Howard Chu
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/string.h>

#define AVL_INTERNAL
#include "avl.h"

static void ravl_print LDAP_P(( Avlnode *root, int depth, int thread ));
static void myprint LDAP_P(( Avlnode *root ));
static int avl_strcmp LDAP_P(( const void *s, const void *t ));

int
main( int argc, char **argv )
{
	Avlnode	*tree = NULL, *n;
	char	command[ 10 ];
	char	name[ 80 ];
	char	*p;

	printf( "> " );
	while ( fgets( command, sizeof( command ), stdin ) != NULL ) {
		switch( *command ) {
		case 'n':	/* new tree */
			( void ) tavl_free( tree, free );
			tree = NULL;
			break;
		case 'p':	/* print */
			( void ) myprint( tree );
			break;
		case 't':	/* traverse with first, next */
			printf( "***\n" );
			for ( n = tavl_end( tree, TAVL_DIR_LEFT );
			    n != NULL;
				n = tavl_next( n, TAVL_DIR_RIGHT ))
				printf( "%s\n", n->avl_data );
			printf( "***\n" );
			break;
		case 'f':	/* find */
			printf( "data? " );
			if ( fgets( name, sizeof( name ), stdin ) == NULL )
				exit( EXIT_SUCCESS );
			name[ strlen( name ) - 1 ] = '\0';
			if ( (p = (char *) tavl_find( tree, name, avl_strcmp ))
			    == NULL )
				printf( "Not found.\n\n" );
			else
				printf( "%s\n\n", p );
			break;
		case 'i':	/* insert */
			printf( "data? " );
			if ( fgets( name, sizeof( name ), stdin ) == NULL )
				exit( EXIT_SUCCESS );
			name[ strlen( name ) - 1 ] = '\0';
			if ( tavl_insert( &tree, strdup( name ), avl_strcmp, 
			    avl_dup_error ) != 0 )
				printf( "\nNot inserted!\n" );
			break;
		case 'd':	/* delete */
			printf( "data? " );
			if ( fgets( name, sizeof( name ), stdin ) == NULL )
				exit( EXIT_SUCCESS );
			name[ strlen( name ) - 1 ] = '\0';
			if ( tavl_delete( &tree, name, avl_strcmp ) == NULL )
				printf( "\nNot found!\n" );
			break;
		case 'q':	/* quit */
			exit( EXIT_SUCCESS );
			break;
		case '\n':
			break;
		default:
			printf("Commands: insert, delete, print, new, quit\n");
		}

		printf( "> " );
	}

	return( 0 );
}

static const char bfc_array[] = "\\-/";
static const char *bfcs = bfc_array+1;

static void ravl_print( Avlnode *root, int depth, int thread )
{
	int	i;

	if ( root && !thread )
	ravl_print( root->avl_link[1], depth+1, root->avl_bits[1] == AVL_THREAD );

	for ( i = 0; i < depth; i++ )
		printf( "   " );
	if ( thread )
		printf( "~" );
	else if ( root )
		printf( "%c", bfcs[root->avl_bf] );
	else
		printf( " " );
	if ( !root) {
		printf( ".\n" );
		return;
	}
	printf( "%s\n", (char *) root->avl_data );

	if ( !thread )
	ravl_print( root->avl_link[0], depth+1, root->avl_bits[0] == AVL_THREAD );
}

static void myprint( Avlnode *root )
{
	printf( "********\n" );

	if ( root == 0 )
		printf( "\tNULL\n" );
	else
		ravl_print( root, 0, 0 );

	printf( "********\n" );
}

static int avl_strcmp( const void *s, const void *t )
{
	return strcmp( s, t );
}
