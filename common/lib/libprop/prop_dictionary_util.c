/*	$NetBSD: prop_dictionary_util.c,v 1.1 2006/10/26 05:02:12 thorpej Exp $	*/

/*-
 * Copyright (c) 2006 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe.
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
 *      This product includes software developed by the NetBSD
 *      Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Utility routines to make it more convenient to work with values
 * stored in dictionaries.
 *
 * Note: There is no special magic going on here.  We use the standard
 * proplib(3) APIs to do all of this work.  Any application could do
 * exactly what we're doing here.
 */

#include <prop/proplib.h>
#include "prop_object_impl.h"	/* only to hide kernel vs. not-kernel */

boolean_t
prop_dictionary_get_bool(prop_dictionary_t dict,
			 const char *key,
			 boolean_t *valp)
{
	prop_bool_t b;

	b = prop_dictionary_get(dict, key);
	if (prop_object_type(b) != PROP_TYPE_BOOL)
		return (FALSE);
	
	*valp = prop_bool_true(b);

	return (TRUE);
}

boolean_t
prop_dictionary_set_bool(prop_dictionary_t dict,
			 const char *key,
			 boolean_t val)
{
	prop_bool_t b;
	int rv;

	b = prop_bool_create(val);
	if (b == NULL)
		return (FALSE);
	rv = prop_dictionary_set(dict, key, b);
	prop_object_release(b);

	return (rv);
}

#define	TEMPLATE(size)							\
boolean_t								\
prop_dictionary_get_int ## size (prop_dictionary_t dict,		\
				 const char *key,			\
				 int ## size ## _t *valp)		\
{									\
	prop_number_t num;						\
									\
	num = prop_dictionary_get(dict, key);				\
	if (prop_object_type(num) != PROP_TYPE_NUMBER)			\
		return (FALSE);						\
									\
	if (prop_number_unsigned(num) &&				\
	    prop_number_unsigned_integer_value(num) >			\
	   /*CONSTCOND*/((size) ==  8 ?  INT8_MAX :			\
			 (size) == 16 ? INT16_MAX :			\
			 (size) == 32 ? INT32_MAX : INT64_MAX)) {	\
		return (FALSE);						\
	}								\
									\
	if (prop_number_size(num) > (size))				\
		return (FALSE);						\
									\
	*valp = (int ## size ## _t) prop_number_integer_value(num);	\
									\
	return (TRUE);							\
}									\
									\
boolean_t								\
prop_dictionary_get_uint ## size (prop_dictionary_t dict,		\
				  const char *key,			\
				  uint ## size ## _t *valp)		\
{									\
	prop_number_t num;						\
									\
	num = prop_dictionary_get(dict, key);				\
	if (prop_object_type(num) != PROP_TYPE_NUMBER)			\
		return (FALSE);						\
									\
	if (prop_number_unsigned(num) == FALSE &&			\
	    prop_number_integer_value(num) < 0) {			\
		return (FALSE);						\
	}								\
									\
	if (prop_number_size(num) > (size))				\
		return (FALSE);						\
									\
	*valp = (uint ## size ## _t)					\
	    prop_number_unsigned_integer_value(num);			\
									\
	return (TRUE);							\
}									\
									\
boolean_t								\
prop_dictionary_set_int ## size (prop_dictionary_t dict,		\
				 const char *key,			\
				 int ## size ## _t val)			\
{									\
	prop_number_t num;						\
	int rv;								\
									\
	num = prop_number_create_integer((int64_t) val);		\
	if (num == NULL)						\
		return (FALSE);						\
	rv = prop_dictionary_set(dict, key, num);			\
	prop_object_release(num);					\
									\
	return (rv);							\
}									\
									\
boolean_t								\
prop_dictionary_set_uint ## size (prop_dictionary_t dict,		\
				  const char *key,			\
				  uint ## size ## _t val)		\
{									\
	prop_number_t num;						\
	int rv;								\
									\
	num = prop_number_create_unsigned_integer((uint64_t) val);	\
	if (num == NULL)						\
		return (FALSE);						\
	rv = prop_dictionary_set(dict, key, num);			\
	prop_object_release(num);					\
									\
	return (rv);							\
}

TEMPLATE(8)
TEMPLATE(16)
TEMPLATE(32)
TEMPLATE(64)

#undef TEMPLATE

#define	TEMPLATE(variant, qualifier)					\
boolean_t								\
prop_dictionary_get_cstring ## variant (prop_dictionary_t dict,		\
					const char *key,		\
					qualifier char **cpp)		\
{									\
	prop_string_t str;						\
									\
	str = prop_dictionary_get(dict, key);				\
	if (prop_object_type(str) != PROP_TYPE_STRING)			\
		return (FALSE);						\
									\
	*cpp = prop_string_cstring ## variant (str);			\
									\
	return (*cpp == NULL ? FALSE : TRUE);				\
}									\
									\
boolean_t								\
prop_dictionary_set_cstring ## variant (prop_dictionary_t dict,		\
					const char *key,		\
					const char *cp)			\
{									\
	prop_string_t str;						\
	int rv;								\
									\
	str = prop_string_create_cstring ## variant (cp);		\
	if (str == NULL)						\
		return (FALSE);						\
	rv = prop_dictionary_set(dict, key, str);			\
	prop_object_release(str);					\
									\
	return (rv);							\
}

TEMPLATE(,)
TEMPLATE(_nocopy,const)

#undef TEMPLATE
