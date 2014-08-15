/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2009-2013 The OpenLDAP Foundation.
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
/* ACKNOWLEDGEMENT:
 * This work was initially developed by David Wright <david@davidwright.co.nz>
 */

#define _GNU_SOURCE

#include "portable.h"
#include <ac/string.h>
#include "lber_pvt.h"
#include "lutil.h"

#include <stdio.h>
#include <stdlib.h>

#include "bcrypt.h"

#define BCRYPT_ITERATION 8

const struct berval bcryptscheme = BER_BVC("{BCRYPT}");

static int bcrypt_encrypt(
	const struct berval *scheme,
	const struct berval *passwd,
	struct berval *msg,
	const char **text)
{
	char salt[BCRYPT_HASHSIZE] = {0};
	char hash[BCRYPT_HASHSIZE] = {0};
	int rc;
	int i = 0;

	rc = bcrypt_gensalt(BCRYPT_ITERATION, salt);
#ifdef SLAPD_BCRYPT_DEBUG
	printf("DEBUG bcrypt_encrypt()\n");
	if(rc != 0) {
		printf("bcrypt_gensalt error %d\n", rc);
	} else {
		printf("bcrypt_gensalt OK %d\n", rc);
	}
	printf("Salt: ");
	for(; i < BCRYPT_HASHSIZE; i++) {
		printf("%c", salt[i]);
	}
	printf("\n");
#endif
	if(rc != 0) return LUTIL_PASSWD_ERR;

	rc = bcrypt_hashpw(passwd->bv_val, salt, hash);
#ifdef SLAPD_BCRYPT_DEBUG
	if(rc != 0) {
		printf("bcrypt_hashpw error %d\n", rc);
	} else {
		printf("bcrypt_hashpw OK %d\n", rc);
	}
#endif
	if(rc != 0) return LUTIL_PASSWD_ERR;

	msg->bv_len = asprintf(&msg->bv_val, "%s%s", scheme->bv_val, hash);

#ifdef SLAPD_BCRYPT_DEBUG
	printf("bcrypt_encrypt() result: ");
	printf("%s%s\n", scheme->bv_val, hash);
#endif

	if(msg->bv_len < 0){
		return LUTIL_PASSWD_ERR;
	}

	return LUTIL_PASSWD_OK;
}

static int bcrypt_check(
	const struct berval *scheme,
	const struct berval *passwd,
	const struct berval *cred,
	const char **text)
{
	int rc;
	int i = 0;
#ifdef SLAPD_BCRYPT_DEBUG
	printf("DEBUG bcrypt_check()\n");
	printf("  Stored Value:\t%s\n", passwd->bv_val);
	printf("  Input Cred:\t%s\n", cred->bv_val);
#endif
	char hash[BCRYPT_HASHSIZE] = {0};
	rc = bcrypt_hashpw(cred->bv_val, passwd->bv_val, hash);

#ifdef SLAPD_BCRYPT_DEBUG
	if(rc != 0) {
		printf("bcrypt_hashpw error %d\n", rc);
	} else {
		printf("bcrypt_hashpw OK %d\n", rc);
	}
#endif

	if(rc != 0) return LUTIL_PASSWD_ERR;

#ifdef SLAPD_BCRYPT_DEBUG
	printf("  Hash:\t%s\n", hash);
#endif

	if (strcmp(passwd->bv_val, hash) == 0) {
		return LUTIL_PASSWD_OK;
 	} else {
		return LUTIL_PASSWD_ERR;
	}
}

int init_module(int argc, char *argv[]) {
	int rc;
	rc = lutil_passwd_add((struct berval *)&bcryptscheme,
						  bcrypt_check, bcrypt_encrypt);
	return rc;
}

/*
 * Local variables:
 * indent-tabs-mode: t
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 */
