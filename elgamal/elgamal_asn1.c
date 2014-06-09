/* elgamal_asn1.c */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 2000-2005 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/*
 * This package is written by Vincent Huang (winscar@stu.xidian.edu.cn)
 * as a tool to do experiments. It can be freely used by anyone.
 * But it is not strong or secure enough to sustain comercial usage.
 * Hope you all happy to use this :-) */

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/elgamal.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

/* Override the default new methods */
static int sig_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
								void *exarg)
{
	if(operation == ASN1_OP_NEW_PRE) {
		ElGamal_SIG *sig;
		sig = OPENSSL_malloc(sizeof(ElGamal_SIG));
		if (!sig)
			{
			ElGamalerr(ElGamal_F_SIG_CB, ERR_R_MALLOC_FAILURE);
			return 0;
			}
		sig->c1 = NULL;
		sig->c2 = NULL;
		*pval = (ASN1_VALUE *)sig;
		return 2;
	}
	return 1;
}
static int sig_cb_ex(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
								void *exarg)
{
	if(operation == ASN1_OP_NEW_PRE) {
		ElGamal_SIG_EX *sig;
		sig = OPENSSL_malloc(sizeof(ElGamal_SIG_EX));
		if (!sig)
			{
			ElGamalerr(ElGamal_F_SIG_CB, ERR_R_MALLOC_FAILURE);
			return 0;
			}
		sig->c1 = NULL;
		sig->c2 = NULL;
		sig->t1 = NULL;
		sig->t2 = NULL;
		*pval = (ASN1_VALUE *)sig;
		return 2;
	}
	return 1;
}


ASN1_SEQUENCE_cb(ElGamal_SIG, sig_cb) = {
	ASN1_SIMPLE(ElGamal_SIG, c1, CBIGNUM),
	ASN1_SIMPLE(ElGamal_SIG, c2, CBIGNUM)
} ASN1_SEQUENCE_END_cb(ElGamal_SIG, ElGamal_SIG)

ASN1_SEQUENCE_cb(ElGamal_SIG_EX, sig_cb_ex) = {
	ASN1_SIMPLE(ElGamal_SIG_EX, c1, CBIGNUM),
	ASN1_SIMPLE(ElGamal_SIG_EX, c2, CBIGNUM),
	ASN1_SIMPLE(ElGamal_SIG_EX, t1, CBIGNUM),
	ASN1_SIMPLE(ElGamal_SIG_EX, t2, CBIGNUM)
} ASN1_SEQUENCE_END_cb(ElGamal_SIG_EX, ElGamal_SIG_EX)


IMPLEMENT_ASN1_FUNCTIONS_const(ElGamal_SIG)

IMPLEMENT_ASN1_FUNCTIONS_const(ElGamal_SIG_EX)

/* Override the default free and new methods */
static int elgamal_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
							void *exarg)
{
	if(operation == ASN1_OP_NEW_PRE) {
		*pval = (ASN1_VALUE *)ElGamal_new();
		if(*pval) return 2;
		return 0;
	} else if(operation == ASN1_OP_FREE_PRE) {
		ElGamal_free((ElGamal *)*pval);
		*pval = NULL;
		return 2;
	}
	return 1;
}

ASN1_SEQUENCE_cb(ElGamalPrivateKey, elgamal_cb) = {
	ASN1_SIMPLE(ElGamal, version, LONG),
	ASN1_SIMPLE(ElGamal, p, BIGNUM),
	ASN1_SIMPLE(ElGamal, q, BIGNUM),
	ASN1_SIMPLE(ElGamal, g, BIGNUM),
	ASN1_SIMPLE(ElGamal, pub_key, BIGNUM),
	ASN1_SIMPLE(ElGamal, priv_key, BIGNUM)
} ASN1_SEQUENCE_END_cb(ElGamal, ElGamalPrivateKey)

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(ElGamal, ElGamalPrivateKey, ElGamalPrivateKey)

ASN1_SEQUENCE_cb(ElGamalparams, elgamal_cb) = {
	ASN1_SIMPLE(ElGamal, p, BIGNUM),
	ASN1_SIMPLE(ElGamal, q, BIGNUM),
	ASN1_SIMPLE(ElGamal, g, BIGNUM),
} ASN1_SEQUENCE_END_cb(ElGamal, ElGamalparams)

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(ElGamal, ElGamalparams, ElGamalparams)

/* ElGamal public key is a bit trickier... its effectively a CHOICE type
 * decided by a field called write_params which can either write out
 * just the public key as an INTEGER or the parameters and public key
 * in a SEQUENCE
 */

ASN1_SEQUENCE(elgamal_pub_internal) = {
	ASN1_SIMPLE(ElGamal, pub_key, BIGNUM),
	ASN1_SIMPLE(ElGamal, p, BIGNUM),
	ASN1_SIMPLE(ElGamal, q, BIGNUM),
	ASN1_SIMPLE(ElGamal, g, BIGNUM)
} ASN1_SEQUENCE_END_name(ElGamal, elgamal_pub_internal)

ASN1_CHOICE_cb(ElGamalPublicKey, elgamal_cb) = {
	ASN1_SIMPLE(ElGamal, pub_key, BIGNUM),
	ASN1_EX_COMBINE(0, 0, elgamal_pub_internal)
} ASN1_CHOICE_END_cb(ElGamal, ElGamalPublicKey, write_params)

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(ElGamal, ElGamalPublicKey, ElGamalPublicKey)

ElGamal *ElGamalparams_dup(ElGamal *elgamal)
	{
	return ASN1_item_dup(ASN1_ITEM_rptr(ElGamalparams), elgamal);
	}
