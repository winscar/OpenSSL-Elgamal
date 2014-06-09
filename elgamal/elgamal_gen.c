/* crypto/elgamal/elgamal_gen.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
 /*
 *
 * Change whole file to get the (p,q,g) needed by elgamal algorithm.
 *
 */

#undef GENUINE_ElGamal

#ifdef GENUINE_ElGamal
/* Parameter generation follows the original release of FIPS PUB 186,
 * Appendix 2.2 (i.e. use SHA as defined in FIPS PUB 180) */
#define HASH    EVP_sha()
#else
/* Parameter generation follows the updated Appendix 2.2 for FIPS PUB 186,
 * also Appendix 2.2 of FIPS PUB 186-1 (i.e. use SHA as defined in
 * FIPS PUB 180-1) */
#define HASH    EVP_sha1()
#endif 

#include <openssl/opensslconf.h> /* To see if OPENSSL_NO_SHA is defined */

#ifndef OPENSSL_NO_SHA

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "elgamal_locl.h"

#define PRIME_P_LENGTH	((1024 + 512)/8)

int ElGamal_generate_parameters_ex(ElGamal *ret, int bits, BIO *bio,
		int *counter_ret, unsigned long *h_ret, BN_GENCB *cb)
	{
	if(ret->meth->elgamal_paramgen)
		return ret->meth->elgamal_paramgen(ret, bits, bio,
				counter_ret, h_ret, cb);
	else
		return elgamal_builtin_paramgen(ret, bits, bio,
				counter_ret, h_ret, cb);
	}

int elgamal_builtin_paramgen(ElGamal *ret, size_t bits, BIO *bio,
				int *counter_ret, unsigned long *h_ret, BN_GENCB *cb)
	{
	int ok=0;
	unsigned char seed[PRIME_P_LENGTH];			/* 128 + 64 bytes */
	BIGNUM *r0,*test;
	BIGNUM *g=NULL,*q=NULL,*p=NULL;
	BN_MONT_CTX *mont=NULL;
	int psize;
	int counter=0;
	int r=0;
	BN_CTX *ctx=NULL;
	unsigned int h=2;
	
	/* pbits need to be multiple of 64*/
	if (bits < 1024)	bits = 1024;
	else			bits = (bits+63)/64*64;
	psize = bits >> 3;							/* psize is measured by bytes */

	/* initialization of BN */
	if ((ctx=BN_CTX_new()) == NULL)
		goto err;

	if ((mont=BN_MONT_CTX_new()) == NULL)
		goto err;

	BN_CTX_start(ctx);
	r0 = BN_CTX_get(ctx);
	g = BN_CTX_get(ctx);
	q = BN_CTX_get(ctx);
	p = BN_CTX_get(ctx);
	test = BN_CTX_get(ctx);


	for (;;) /* find p */
		{
		/* step 1 */
		if(!BN_GENCB_call(cb, counter++, 0))
			goto err;

		RAND_pseudo_bytes(seed, psize);

		/* step 3 */
		seed[0] |= 0x80;
		seed[psize-1] |= 0x01;
		if (!BN_bin2bn(seed, psize, p))	goto err;

		/* step 4 */
		r = BN_is_prime_fasttest_ex(p, DSS_prime_checks, ctx, 1, cb);
			
		if (r > 0)
			{		
			/* step 5 */
			if(!BN_GENCB_call(cb, 2, 0)) goto err;
			if(!BN_GENCB_call(cb, 3, 0)) goto err;
						
			/* step 6 */ /* q=(p-1)/2 */
			if (!BN_sub(r0,p,BN_value_one()))	goto err;
			if (!BN_rshift1(q,r0))				goto err;
			
			/* step 7 */
			r = BN_is_prime_fasttest_ex(p, DSS_prime_checks, ctx, 1, cb);
			
			if (r > 0)
				{
					/* step 8 */
					if(!BN_GENCB_call(cb, 2, 0)) goto err;
					if(!BN_GENCB_call(cb, 3, 0)) goto err;
					
					/* step 9*/
					break;
				}
			if (r != 0) goto err;
			}
		if (r != 0)	goto err;

		/* do a callback call */
		}

	if(!BN_GENCB_call(cb, 2, 1))	goto err;

	/* We now need to generate g */
	/* Set r0=(p-1)/q=2 */
	if (!BN_add(r0,BN_value_one(),BN_value_one()))	goto err;

	if (!BN_set_word(test,h)) goto err;
	if (!BN_MONT_CTX_set(mont,p,ctx)) goto err;

	for (;;)
		{
		/* g=test^r0%p */
		if (!BN_mod_exp_mont(g,test,r0,p,ctx,mont))	goto err;
		if (!BN_is_one(g)) break;
		if (!BN_add(test,test,BN_value_one()))		goto err;
		h++;
		}

	if(!BN_GENCB_call(cb, 3, 1))	goto err;

	ok=1;
err:
	if (ok)
		{
		if(ret->p) BN_free(ret->p);
		if(ret->q) BN_free(ret->q);
		if(ret->g) BN_free(ret->g);
		ret->p=BN_dup(p);
		ret->q=BN_dup(q);
		ret->g=BN_dup(g);
		if (ret->p == NULL || ret->q == NULL || ret->g == NULL)
			{
			ok=0;
			goto err;
			}
		if (counter_ret != NULL) *counter_ret=counter;
		if (h_ret != NULL) *h_ret=h;
		}
	if(ctx)
		{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
		}
	if (mont != NULL) BN_MONT_CTX_free(mont);
	return ok;
	}
#endif

