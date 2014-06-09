/* crypto/elgamal/elgamal_ossl.c */
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

/* Original version from Steven Schoch <schoch@sheba.arc.nasa.gov> */

/*
 * This package is written by Vincent Huang (winscar@stu.xidian.edu.cn)
 * as a tool to do experiments. It can be freely used by anyone.
 * But it is not strong or secure enough to sustain comercial usage.
 * Hope you all happy to use this :-) */

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/elgamal.h>
#include <openssl/rand.h>
#include <openssl/asn1.h>

static ElGamal_SIG *elgamal_do_encrypt(const unsigned char *msg, int msglen, ElGamal *elgamal);
static ElGamal_SIG_EX *elgamal_do_encrypt_ex(const unsigned char *msg, int msglen, ElGamal *elgamal);
static int elgamal_encrypt_setup(ElGamal *elgamal, BN_CTX *ctx_in, BIGNUM **yk, BIGNUM **gk);
static ElGamal_SIG *elgamal_do_reencrypt(ElGamal_SIG *cipher, ElGamal *elgamal);
static ElGamal_SIG_EX *elgamal_do_reencrypt_ex(ElGamal_SIG_EX *cipher, ElGamal *elgamal);
static int elgamal_do_decrypt(unsigned char *msg, int *msglen, const ElGamal_SIG *cipher,ElGamal *elgamal);
static int elgamal_do_decrypt_ex(unsigned char *msg, int *msglen, const ElGamal_SIG_EX *cipher,ElGamal *elgamal);
static int elgamal_init(ElGamal *elgamal);
static int elgamal_finish(ElGamal *elgamal);

static ElGamal_METHOD openssl_elgamal_meth = {
"OpenSSL ElGamal method",
elgamal_do_encrypt,
elgamal_do_encrypt_ex,
elgamal_encrypt_setup,
elgamal_do_reencrypt,
elgamal_do_reencrypt_ex,
elgamal_do_decrypt,
elgamal_do_decrypt_ex,
NULL, /* elgamal_mod_exp, */
NULL, /* elgamal_bn_mod_exp, */
elgamal_init,
elgamal_finish,
0,
NULL,
NULL,
NULL
};

/* These macro wrappers replace attempts to use the elgamal_mod_exp() and
 * bn_mod_exp() handlers in the ElGamal_METHOD structure. We avoid the problem of
 * having a the macro work as an expression by bundling an "err_instr". So;
 * 
 *     if (!elgamal->meth->bn_mod_exp(elgamal, r,elgamal->g,&k,elgamal->p,ctx,
 *                 elgamal->method_mont_p)) goto err;
 *
 * can be replaced by;
 *
 *     ElGamal_BN_MOD_EXP(goto err, elgamal, r, elgamal->g, &k, elgamal->p, ctx,
 *                 elgamal->method_mont_p);
 */

#define ElGamal_MOD_EXP(err_instr,elgamal,rr,a1,p1,a2,p2,m,ctx,in_mont) \
	do { \
	int _tmp_res53; \
	if((elgamal)->meth->elgamal_mod_exp) \
		_tmp_res53 = (elgamal)->meth->elgamal_mod_exp((elgamal), (rr), (a1), (p1), \
				(a2), (p2), (m), (ctx), (in_mont)); \
	else \
		_tmp_res53 = BN_mod_exp2_mont((rr), (a1), (p1), (a2), (p2), \
				(m), (ctx), (in_mont)); \
	if(!_tmp_res53) err_instr; \
	} while(0)
#define ElGamal_BN_MOD_EXP(err_instr,elgamal,r,a,p,m,ctx,m_ctx) \
	do { \
	int _tmp_res53; \
	if((elgamal)->meth->bn_mod_exp) \
		_tmp_res53 = (elgamal)->meth->bn_mod_exp((elgamal), (r), (a), (p), \
				(m), (ctx), (m_ctx)); \
	else \
		_tmp_res53 = BN_mod_exp_mont((r), (a), (p), (m), (ctx), (m_ctx)); \
	if(!_tmp_res53) err_instr; \
	} while(0)

const ElGamal_METHOD *ElGamal_OpenSSL(void)
{
	return &openssl_elgamal_meth;
}

static ElGamal_SIG *elgamal_do_encrypt(const unsigned char *msg, int msglen, ElGamal *elgamal)
	{
	BIGNUM *c1=NULL,*c2=NULL;
	BIGNUM m;
	BIGNUM *yk=NULL,*gk=NULL;
	BN_CTX *ctx=NULL;
	int reason=ERR_R_BN_LIB;
	ElGamal_SIG *ret=NULL;

	BN_init(&m);
	if ((c1=BN_new()) == NULL) goto err;

	if (!elgamal->p || !elgamal->q || !elgamal->g)
		{
		reason=ElGamal_R_MISSING_PARAMETERS;
		goto err;
		}
		
	ctx=BN_CTX_new();
	if (ctx == NULL) goto err;

	if (!ElGamal_encrypt_setup(elgamal,ctx,&yk,&gk)) goto err;
	
	if (msglen > BN_num_bytes(elgamal->p))
		/* if the digest length is greater than the size of q use the
		 * BN_num_bits(elgamal->p) leftmost bits of the digest, see
		 * fips 186-3, 4.2 */
		msglen = BN_num_bytes(elgamal->p);
	if (BN_bin2bn(msg,msglen,&m) == NULL)
		goto err;

	/* Compute c1 = m * yk (mod p) and c2 = gk (mod p) */
	if (!BN_mod_mul(c1,&m,yk,elgamal->p,ctx)) goto err;
	if (!(c2 = BN_dup(gk))) goto err;

	ret=ElGamal_SIG_new();
	if (ret == NULL) goto err;
	ret->c1 = c1;
	ret->c2 = c2;

err:
	if (!ret)
		{
		ElGamalerr(ElGamal_F_ElGamal_DO_SIGN,reason);
		BN_free(c1);
		BN_free(c2);
		}
	if (ctx != NULL) BN_CTX_free(ctx);
	BN_clear_free(&m);
	BN_clear_free(yk);
	BN_clear_free(gk);
	
	return(ret);
	}

static ElGamal_SIG_EX *elgamal_do_encrypt_ex(const unsigned char *msg, int msglen, ElGamal *elgamal)
{
	BIGNUM *c1=NULL,*c2=NULL;
	BIGNUM *t1=NULL,*t2=NULL;
	BIGNUM m;
	BIGNUM *yk=NULL,*gk=NULL;
	BIGNUM *yr=NULL,*gr=NULL;
	BN_CTX *ctx=NULL;
	int reason=ERR_R_BN_LIB;
	ElGamal_SIG_EX *ret=NULL;

	BN_init(&m);
	if ((c1=BN_new()) == NULL) goto err;

	if (!elgamal->p || !elgamal->q || !elgamal->g)
		{
		reason=ElGamal_R_MISSING_PARAMETERS;
		goto err;
		}
		
	ctx=BN_CTX_new();
	if (ctx == NULL) goto err;

	if (!ElGamal_encrypt_setup(elgamal,ctx,&yk,&gk)) goto err;
	
	if (msglen > BN_num_bytes(elgamal->p))
		/* if the digest length is greater than the size of q use the
		 * BN_num_bits(elgamal->p) leftmost bits of the digest, see
		 * fips 186-3, 4.2 */
		msglen = BN_num_bytes(elgamal->p);
	if (BN_bin2bn(msg,msglen,&m) == NULL)
		goto err;

	/* Compute c1 = m * yk (mod p) and c2 = gk (mod p) */
	if (!BN_mod_mul(c1,&m,yk,elgamal->p,ctx)) goto err;
	if (!(c2 = BN_dup(gk))) goto err;

	/* Compute t1 = yr (mod p) and t2 = gr (mod p) */
	if (!ElGamal_encrypt_setup(elgamal,ctx,&yr,&gr)) goto err;

	ret=ElGamal_SIG_EX_new();
	if (ret == NULL) goto err;
	ret->c1 = c1;
	ret->c2 = c2;

	t1 = BN_dup(yr);
	t2 = BN_dup(gr);
	ret->t1 = t1;
	ret->t2 = t2;

err:
	if (!ret)
		{
		ElGamalerr(ElGamal_F_ElGamal_DO_SIGN,reason);
		BN_free(c1);
		BN_free(c2);
		BN_free(t1);
		BN_free(t2);
		}
	if (ctx != NULL) BN_CTX_free(ctx);
	BN_clear_free(&m);
	BN_clear_free(yk);
	BN_clear_free(gk);
	BN_clear_free(yr);
	BN_clear_free(gr);
	
	return(ret);
}

static int elgamal_encrypt_setup(ElGamal *elgamal, BN_CTX *ctx_in, BIGNUM **yk, BIGNUM **gk)
	{
	BN_CTX *ctx;
	BIGNUM k,kq,*K,*yr=NULL,*gr=NULL;
	int ret=0;

	if (!elgamal->p || !elgamal->q || !elgamal->g)
		{
		ElGamalerr(ElGamal_F_ElGamal_SIGN_SETUP,ElGamal_R_MISSING_PARAMETERS);
		return 0;
		}

	BN_init(&k);
	BN_init(&kq);

	if (ctx_in == NULL)
		{
		if ((ctx=BN_CTX_new()) == NULL) goto err;
		}
	else
		ctx=ctx_in;

	if ((yr=BN_new()) == NULL) goto err;
	if ((gr=BN_new()) == NULL) goto err;

	/* Get random k */
	do
		if (!BN_rand_range(&k, elgamal->q)) goto err;
	while (BN_is_zero(&k));
	if ((elgamal->flags & ElGamal_FLAG_NO_EXP_CONSTTIME) == 0)
		{
		BN_set_flags(&k, BN_FLG_CONSTTIME);
		}

	if (elgamal->flags & ElGamal_FLAG_CACHE_MONT_P)
		{
		if (!BN_MONT_CTX_set_locked(&elgamal->method_mont_p,
						CRYPTO_LOCK_ElGamal,
						elgamal->p, ctx))
			goto err;
		}

	/* Compute yr = (y^k mod p) and gr = (g^k mod p) */
	if ((elgamal->flags & ElGamal_FLAG_NO_EXP_CONSTTIME) == 0)
		{
		if (!BN_copy(&kq, &k)) goto err;

		/* We do not want timing information to leak the length of k,
		 * so we compute g^k using an equivalent exponent of fixed length.
		 *
		 * (This is a kludge that we need because the BN_mod_exp_mont()
		 * does not let us specify the desired timing behaviour.) */

		if (!BN_add(&kq, &kq, elgamal->q)) goto err;
		if (BN_num_bits(&kq) <= BN_num_bits(elgamal->q))
			{
			if (!BN_add(&kq, &kq, elgamal->q)) goto err;
			}

		K = &kq;
		}
	else
		{
		K = &k;
		}
	ElGamal_BN_MOD_EXP(goto err, elgamal, yr, elgamal->pub_key, K, elgamal->p, ctx,
			elgamal->method_mont_p);
	ElGamal_BN_MOD_EXP(goto err, elgamal, gr, elgamal->g, K, elgamal->p, ctx,
			elgamal->method_mont_p);
			
	if (*yk != NULL) BN_clear_free(*yk);
	*yk=yr;
	yr=NULL;
	if (*gk != NULL) BN_clear_free(*gk);
	*gk=gr;
	gr=NULL;
	
	ret=1;
err:
	if (!ret)
		{
		ElGamalerr(ElGamal_F_ElGamal_SIGN_SETUP,ERR_R_BN_LIB);
		if (yr != NULL)
			BN_clear_free(yr);
		if (gr != NULL)
			BN_clear_free(gr);
		}
	if (ctx_in == NULL) BN_CTX_free(ctx);
	BN_clear_free(&k);
	BN_clear_free(&kq);
	return(ret);
	}

static ElGamal_SIG *elgamal_do_reencrypt(ElGamal_SIG *cipher, ElGamal *elgamal)
	{
	int ret=0;

	BN_CTX *ctx=NULL;
	BIGNUM k,kq,*K,*yr=NULL,*gr=NULL,*c1=NULL,*c2=NULL;

	if (!cipher->c1 || !cipher->c2 || !elgamal) goto err;

	BN_init(&k);
	BN_init(&kq);

	if ((ctx=BN_CTX_new()) == NULL) goto err;
	
	if ((yr=BN_new()) == NULL) goto err;
	if ((gr=BN_new()) == NULL) goto err;
	if ((c1=BN_new()) == NULL) goto err;
	if ((c2=BN_new()) == NULL) goto err;

	/* Get random k */
	do
		if (!BN_rand_range(&k, elgamal->q)) goto err;
	while (BN_is_zero(&k));

	/* Compute yr and gr */
	if ((elgamal->flags & ElGamal_FLAG_NO_EXP_CONSTTIME) == 0)
		{
		if (!BN_copy(&kq, &k)) goto err;

		/* We do not want timing information to leak the length of k,
		 * so we compute g^k using an equivalent exponent of fixed length.
		 *
		 * (This is a kludge that we need because the BN_mod_exp_mont()
		 * does not let us specify the desired timing behaviour.) */

		if (!BN_add(&kq, &kq, elgamal->q)) goto err;
		if (BN_num_bits(&kq) <= BN_num_bits(elgamal->q))
			{
			if (!BN_add(&kq, &kq, elgamal->q)) goto err;
			}

		K = &kq;
		}
	else
		{
		K = &k;
		}
	ElGamal_BN_MOD_EXP(goto err, elgamal, yr, elgamal->pub_key, K, elgamal->p, ctx,
			elgamal->method_mont_p);
	ElGamal_BN_MOD_EXP(goto err, elgamal, gr, elgamal->g, K, elgamal->p, ctx,
			elgamal->method_mont_p);
	if (!BN_mod_mul(c1,cipher->c1,yr,elgamal->p,ctx)) goto err;
	if (!BN_mod_mul(c2,cipher->c2,gr,elgamal->p,ctx)) goto err;

	BN_clear_free(cipher->c1);
	BN_clear_free(cipher->c2);

	cipher->c1 = c1;
	cipher->c2 = c2;

	ret = 1;
err:
	if (!ret)
		{
		ElGamalerr(ElGamal_F_ElGamal_DO_SIGN,ERR_R_BN_LIB);
		if (c1 != NULL)
			BN_clear_free(c1);
		if (c2 != NULL)
			BN_clear_free(c2);
		}
	if (yr != NULL)
		BN_clear_free(yr);
	if (gr != NULL)
		BN_clear_free(gr);
	if (ctx != NULL) BN_CTX_free(ctx);
	BN_clear_free(&k);
	BN_clear_free(&kq);
	return(cipher);
	}

static ElGamal_SIG_EX *elgamal_do_reencrypt_ex(ElGamal_SIG_EX *cipher, ElGamal *elgamal)
	{
	int ret=0;

	BN_CTX *ctx=NULL;
	BIGNUM k,kq,*K,*yr=NULL,*gr=NULL;

	if (!cipher->c1 || !cipher->c2 || !cipher->t1 || !cipher->t2 || !elgamal)	goto err;

	BN_init(&k);
	BN_init(&kq);

	if ((ctx=BN_CTX_new()) == NULL) goto err;
	
	if ((yr=BN_new()) == NULL) goto err;
	if ((gr=BN_new()) == NULL) goto err;

	/* Get random k */
	do
		if (!BN_rand_range(&k, elgamal->q)) goto err;
	while (BN_is_zero(&k));

	/* Compute yr and gr */
	if ((elgamal->flags & ElGamal_FLAG_NO_EXP_CONSTTIME) == 0)
		{
		if (!BN_copy(&kq, &k)) goto err;

		/* We do not want timing information to leak the length of k,
		 * so we compute g^k using an equivalent exponent of fixed length.
		 *
		 * (This is a kludge that we need because the BN_mod_exp_mont()
		 * does not let us specify the desired timing behaviour.) */

		if (!BN_add(&kq, &kq, elgamal->q)) goto err;
		if (BN_num_bits(&kq) <= BN_num_bits(elgamal->q))
			{
			if (!BN_add(&kq, &kq, elgamal->q)) goto err;
			}

		K = &kq;
		}
	else
		{
		K = &k;
		}
	ElGamal_BN_MOD_EXP(goto err, elgamal, yr, cipher->t1, K, elgamal->p, ctx,
			elgamal->method_mont_p);
	ElGamal_BN_MOD_EXP(goto err, elgamal, gr, cipher->t2, K, elgamal->p, ctx,
			elgamal->method_mont_p);
	if (!BN_mod_mul(cipher->c1,cipher->c1,yr,elgamal->p,ctx)) goto err;
	if (!BN_mod_mul(cipher->c2,cipher->c2,gr,elgamal->p,ctx)) goto err;

	/* Get random k */
	do
		if (!BN_rand_range(&k, elgamal->q)) goto err;
	while (BN_is_zero(&k));

	/* Compute yr and gr */
	if ((elgamal->flags & ElGamal_FLAG_NO_EXP_CONSTTIME) == 0)
		{
		if (!BN_copy(&kq, &k)) goto err;

		/* We do not want timing information to leak the length of k,
		 * so we compute g^k using an equivalent exponent of fixed length.
		 *
		 * (This is a kludge that we need because the BN_mod_exp_mont()
		 * does not let us specify the desired timing behaviour.) */

		if (!BN_add(&kq, &kq, elgamal->q)) goto err;
		if (BN_num_bits(&kq) <= BN_num_bits(elgamal->q))
			{
			if (!BN_add(&kq, &kq, elgamal->q)) goto err;
			}

		K = &kq;
		}
	else
		{
		K = &k;
		}
	ElGamal_BN_MOD_EXP(goto err, elgamal, cipher->t1, cipher->t1, K, elgamal->p, ctx,
			elgamal->method_mont_p);
	ElGamal_BN_MOD_EXP(goto err, elgamal, cipher->t2, cipher->t2, K, elgamal->p, ctx,
			elgamal->method_mont_p);

	ret = 1;
err:
	if (!ret)
		{
		ElGamalerr(ElGamal_F_ElGamal_DO_SIGN,ERR_R_BN_LIB);
		if (yr != NULL)
			BN_clear_free(yr);
		if (gr != NULL)
			BN_clear_free(gr);
		}
	if (ctx != NULL) BN_CTX_free(ctx);
	BN_clear_free(&k);
	BN_clear_free(&kq);
	return(cipher);
	}

static int elgamal_do_decrypt(unsigned char *msg, int *msglen, const ElGamal_SIG *cipher, ElGamal *elgamal)
	{
	BN_CTX *ctx;
	BIGNUM u1,u2,t1,t2;
	BN_MONT_CTX *mont=NULL;
	int ret = -1,i;
	
	i = BN_num_bits(elgamal->p);
	
	if (!elgamal->p || !elgamal->q || !elgamal->g)
		{
		ElGamalerr(ElGamal_F_ElGamal_DO_VERIFY,ElGamal_R_MISSING_PARAMETERS);
		return -1;
		}

	if (BN_num_bits(elgamal->p) > OPENSSL_ElGamal_MAX_MODULUS_BITS)
		{
		ElGamalerr(ElGamal_F_ElGamal_DO_VERIFY,ElGamal_R_MODULUS_TOO_LARGE);
		return -1;
		}

	BN_init(&u1);
	BN_init(&u2);
	BN_init(&t1);
	BN_init(&t2);

	if ((ctx=BN_CTX_new()) == NULL) goto err;

	if (BN_is_zero(cipher->c1) || BN_is_negative(cipher->c1) ||
	    BN_ucmp(cipher->c1, elgamal->p) >= 0)
		{
		ret = 0;
		goto err;
		}
	if (BN_is_zero(cipher->c2) || BN_is_negative(cipher->c2) ||
	    BN_ucmp(cipher->c2, elgamal->p) >= 0)
		{
		ret = 0;
		goto err;
		}

	/* Calculate W = inv(gk ^ x) mod p
	 * save W in u2 */
	ElGamal_BN_MOD_EXP(goto err, elgamal, &t1, cipher->c2,
			elgamal->priv_key, elgamal->p, ctx, elgamal->method_mont_p);
	if ((BN_mod_inverse(&u2,&t1,elgamal->p,ctx)) == NULL) goto err;
	
	/* t2 = M * W mod p */
	if (!BN_mod_mul(&t2,cipher->c1,&u2,elgamal->p,ctx)) goto err;

	if (!(*msglen = BN_bn2bin(&t2,msg))) goto err;

	if (elgamal->flags & ElGamal_FLAG_CACHE_MONT_P)
		{
		mont = BN_MONT_CTX_set_locked(&elgamal->method_mont_p,
					CRYPTO_LOCK_ElGamal, elgamal->p, ctx);
		if (!mont)
			goto err;
		}

	ret = 1;
err:
	/* XXX: surely this is wrong - if ret is 0, it just didn't decrypt;
	   there is no error in BN. Test should be ret == -1 (Ben) */
	if (ret != 1) ElGamalerr(ElGamal_F_ElGamal_DO_VERIFY,ERR_R_BN_LIB);
	if (ctx != NULL) BN_CTX_free(ctx);

	BN_free(&u1);
	BN_free(&u2);
	BN_free(&t1);
	BN_free(&t2);

	return(ret);
	}

static int elgamal_do_decrypt_ex(unsigned char *msg, int *msglen, const ElGamal_SIG_EX *cipher, ElGamal *elgamal)
{
	ElGamal_SIG *ccipher;
	ElGamal_SIG *tcipher;

	//unsigned char check[0];
	//int checklen;

	ccipher = ElGamal_SIG_new();
	tcipher = ElGamal_SIG_new();

	if(cipher == NULL || elgamal == NULL || msg == NULL) return 0;

	ccipher->c1 = cipher->c1;
	ccipher->c2 = cipher->c2;
	tcipher->c1 = cipher->t1;
	tcipher->c2 = cipher->t2;

	//here should check the tcipher to be bn_one so to return true
	//elgamal_do_decrypt(check, &checklen, tcipher, elgamal);

	elgamal_do_decrypt(msg, msglen, ccipher, elgamal);

	return 1;
}

static int elgamal_init(ElGamal *elgamal)
{
	elgamal->flags|=ElGamal_FLAG_CACHE_MONT_P;
	return(1);
}

static int elgamal_finish(ElGamal *elgamal)
{
	if(elgamal->method_mont_p)
		BN_MONT_CTX_free(elgamal->method_mont_p);
	return(1);
}


