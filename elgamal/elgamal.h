/* crypto/elgamal/elgamal.h */
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
 * This package is written by Vincent Huang (winscar@stu.xidian.edu.cn)
 * as a tool to do experiments. It can be freely used by anyone.
 * But it is not strong or secure enough to sustain comercial usage.
 * Hope you all happy to use this :-) */

#ifndef HEADER_ElGamal_H
#define HEADER_ElGamal_H

#include <openssl/e_os2.h>

#ifdef OPENSSL_NO_ElGamal
#error ElGamal is disabled.
#endif

#ifndef OPENSSL_NO_BIO
#include <openssl/bio.h>
#endif
#include <openssl/crypto.h>
#include <openssl/ossl_typ.h>

#ifndef OPENSSL_NO_DEPRECATED
#include <openssl/bn.h>
#ifndef OPENSSL_NO_DH
# include <openssl/dh.h>
#endif
#endif

#ifndef OPENSSL_ElGamal_MAX_MODULUS_BITS
# define OPENSSL_ElGamal_MAX_MODULUS_BITS	10000
#endif

#define ElGamal_FLAG_CACHE_MONT_P	0x01
#define ElGamal_FLAG_NO_EXP_CONSTTIME       0x02 /* new with 0.9.7h; the built-in ElGamal
                                              * implementation now uses constant time
                                              * modular exponentiation for secret exponents
                                              * by default. This flag causes the
                                              * faster variable sliding window method to
                                              * be used for all exponents.
                                              */

#ifdef  __cplusplus
extern "C" {
#endif

/* Already defined in ossl_typ.h */
typedef struct elgamal_st ElGamal;
typedef struct elgamal_method ElGamal_METHOD;

typedef struct ElGamal_SIG_st
	{
	BIGNUM *c1;			/* m*y^k */
	BIGNUM *c2;			/* g^k */
	} ElGamal_SIG;

typedef struct ElGamal_SIG_EX_st
	{
	BIGNUM *c1;			/* m*y^k */
	BIGNUM *c2;			/* g^k */
	BIGNUM *t1;			/* y^r */
	BIGNUM *t2;			/* g^r */
	} ElGamal_SIG_EX;

struct elgamal_method
	{
	const char *name;
	ElGamal_SIG * (*elgamal_do_encrypt)(const unsigned char *msg, int msglen, ElGamal *elgamal);
	ElGamal_SIG_EX *(*elgamal_do_encrypt_ex)(const unsigned char *msg, int msglen, ElGamal *elgamal);
	int (*elgamal_encrypt_setup)(ElGamal *elgamal, BN_CTX *ctx_in, BIGNUM **yk, BIGNUM **gk);
	ElGamal_SIG * (*elgamal_do_reencrypt)(ElGamal_SIG *cipher, ElGamal *elgamal);
	ElGamal_SIG_EX * (*elgamal_do_reencrypt_ex)(ElGamal_SIG_EX *cipher, ElGamal *elgamal);
	int (*elgamal_do_decrypt)(unsigned char *msg, int *msglen,
			     const ElGamal_SIG *cipher, ElGamal *elgamal);
	int (*elgamal_do_decrypt_ex)(unsigned char *msg, int *msglen,
			     const ElGamal_SIG_EX *cipher, ElGamal *elgamal);
	int (*elgamal_mod_exp)(ElGamal *elgamal, BIGNUM *rr, BIGNUM *a1, BIGNUM *p1,
			BIGNUM *a2, BIGNUM *p2, BIGNUM *m, BN_CTX *ctx,
			BN_MONT_CTX *in_mont);
	int (*bn_mod_exp)(ElGamal *elgamal, BIGNUM *r, BIGNUM *a, const BIGNUM *p,
				const BIGNUM *m, BN_CTX *ctx,
				BN_MONT_CTX *m_ctx); /* Can be null */
	int (*init)(ElGamal *elgamal);
	int (*finish)(ElGamal *elgamal);
	int flags;
	char *app_data;
	/* If this is non-NULL, it is used to generate ElGamal parameters */
	int (*elgamal_paramgen)(ElGamal *elgamal, int bits, BIO *bio,
			int *counter_ret, unsigned long *h_ret,
			BN_GENCB *cb);
	/* If this is non-NULL, it is used to generate ElGamal keys */
	int (*elgamal_keygen)(ElGamal *elgamal);
	};

struct elgamal_st
	{
	/* This first variable is used to pick up errors where
	 * a ElGamal is passed instead of of a EVP_PKEY */
	int pad;
	long version;
	int write_params;
	BIGNUM *p;
	BIGNUM *q;	/* == 20 */
	BIGNUM *g;

	BIGNUM *pub_key;  /* y public key */
	BIGNUM *priv_key; /* x private key */

	BIGNUM *kinv;	/* Signing pre-calc */
	BIGNUM *r;	/* Signing pre-calc */

	int flags;
	/* Normally used to cache montgomery values */
	BN_MONT_CTX *method_mont_p;
	int references;
	CRYPTO_EX_DATA ex_data;
	const ElGamal_METHOD *meth;
	/* functional reference if 'meth' is ENGINE-provided */
	ENGINE *engine;
	};

#define d2i_ElGamalparams_fp(fp,x) (ElGamal *)ASN1_d2i_fp((char *(*)())ElGamal_new, \
		(char *(*)())d2i_ElGamalparams,(fp),(unsigned char **)(x))
#define i2d_ElGamalparams_fp(fp,x) ASN1_i2d_fp(i2d_ElGamalparams,(fp), \
		(unsigned char *)(x))
#define d2i_ElGamalparams_bio(bp,x) ASN1_d2i_bio_of(ElGamal,ElGamal_new,d2i_ElGamalparams,bp,x)
#define i2d_ElGamalparams_bio(bp,x) ASN1_i2d_bio_of_const(ElGamal,i2d_ElGamalparams,bp,x)


ElGamal *ElGamalparams_dup(ElGamal *x);
ElGamal_SIG * ElGamal_SIG_new(void);
ElGamal_SIG_EX * ElGamal_SIG_EX_new(void);
void	ElGamal_SIG_free(ElGamal_SIG *a);
void	ElGamal_SIG_EX_free(ElGamal_SIG_EX *a);
int	i2d_ElGamal_SIG(const ElGamal_SIG *a, unsigned char **pp);
int	i2d_ElGamal_SIG_EX(const ElGamal_SIG_EX *a, unsigned char **pp);
ElGamal_SIG * d2i_ElGamal_SIG(ElGamal_SIG **v, const unsigned char **pp, long length);
ElGamal_SIG_EX * d2i_ElGamal_SIG_EX(ElGamal_SIG_EX **v, const unsigned char **pp, long length);

ElGamal_SIG * ElGamal_do_encrypt(const unsigned char *dgst,int dlen,ElGamal *elgamal);
ElGamal_SIG_EX * ElGamal_do_encrypt_ex(const unsigned char *dgst,int dlen,ElGamal *elgamal);
int	ElGamal_do_decrypt(unsigned char *dgst,int *dgst_len,
		      const ElGamal_SIG *sig,ElGamal *elgamal);
int	ElGamal_do_decrypt_ex(unsigned char *dgst,int *dgst_len,
		      const ElGamal_SIG_EX *sig,ElGamal *elgamal);

ElGamal_SIG * ElGamal_do_reencrypt(ElGamal_SIG *cipher, ElGamal *elgamal);
ElGamal_SIG_EX *ElGamal_do_reencrypt_ex(ElGamal_SIG_EX *cipher, ElGamal *elgamal);

const ElGamal_METHOD *ElGamal_OpenSSL(void);

void	ElGamal_set_default_method(const ElGamal_METHOD *);
const ElGamal_METHOD *ElGamal_get_default_method(void);
int	ElGamal_set_method(ElGamal *elgamal, const ElGamal_METHOD *);

ElGamal *	ElGamal_new(void);
ElGamal *	ElGamal_new_method(ENGINE *engine);
void	ElGamal_free (ElGamal *r);
/* "up" the ElGamal object's reference count */
int	ElGamal_up_ref(ElGamal *r);
int	ElGamal_size(const ElGamal *);
	/* next 4 return -1 on error */
int	ElGamal_encrypt_setup( ElGamal *elgamal,BN_CTX *ctx_in,BIGNUM **yk,BIGNUM **gk);
int	ElGamal_encrypt(int type,const unsigned char *dgst,int dlen,
		unsigned char *sig, unsigned int *siglen, ElGamal *elgamal);
int	ElGamal_encrypt_ex(int type,const unsigned char *dgst,int dlen,
		unsigned char *sig, unsigned int *siglen, ElGamal *elgamal);
int	ElGamal_reencrypt(int type, unsigned char *msg, int *msglen,
	     const unsigned char *cipher, int cipherlen, ElGamal *elgamal);
int	ElGamal_reencrypt_ex(int type, unsigned char *msg, int *msglen,
	     const unsigned char *cipher, int cipherlen, ElGamal *elgamal);
int	ElGamal_decrypt(int type, unsigned char *dgst,int *dgst_len,
		const unsigned char *sigbuf, int siglen, ElGamal *elgamal);
int	ElGamal_decrypt_ex(int type, unsigned char *dgst,int *dgst_len,
		const unsigned char *sigbuf, int siglen, ElGamal *elgamal);
int ElGamal_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
	     CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int ElGamal_set_ex_data(ElGamal *d, int idx, void *arg);
void *ElGamal_get_ex_data(ElGamal *d, int idx);

ElGamal *	d2i_ElGamalPublicKey(ElGamal **a, const unsigned char **pp, long length);
ElGamal *	d2i_ElGamalPrivateKey(ElGamal **a, const unsigned char **pp, long length);
ElGamal * 	d2i_ElGamalparams(ElGamal **a, const unsigned char **pp, long length);

/* Deprecated version */
#ifndef OPENSSL_NO_DEPRECATED
ElGamal *	ElGamal_generate_parameters(int bits, BIO *bio,
		int *counter_ret, unsigned long *h_ret,void
		(*callback)(int, int, void *),void *cb_arg);
#endif /* !defined(OPENSSL_NO_DEPRECATED) */

/* New version */
int	ElGamal_generate_parameters_ex(ElGamal *elgamal, int bits, BIO *bio,
		int *counter_ret, unsigned long *h_ret, BN_GENCB *cb);

int	ElGamal_generate_key(ElGamal *a);
int	i2d_ElGamalPublicKey(const ElGamal *a, unsigned char **pp);
int 	i2d_ElGamalPrivateKey(const ElGamal *a, unsigned char **pp);
int	i2d_ElGamalparams(const ElGamal *a,unsigned char **pp);

#ifndef OPENSSL_NO_BIO
int	ElGamalparams_print(BIO *bp, const ElGamal *x);
int	ElGamal_print(BIO *bp, const ElGamal *x, int off);
#endif
#ifndef OPENSSL_NO_FP_API
int	ElGamalparams_print_fp(FILE *fp, const ElGamal *x);
int	ElGamal_print_fp(FILE *bp, const ElGamal *x, int off);
#endif

#define DSS_prime_checks 50
/* Primality test according to FIPS PUB 186[-1], Appendix 2.1:
 * 50 rounds of Rabin-Miller */
#define ElGamal_is_prime(n, callback, cb_arg) \
	BN_is_prime(n, DSS_prime_checks, callback, NULL, cb_arg)

#ifndef OPENSSL_NO_DH
/* Convert ElGamal structure (key or just parameters) into DH structure
 * (be careful to avoid small subgroup attacks when using this!) */
DH *ElGamal_dup_DH(const ElGamal *r);
#endif

#define EVP_PKEY_CTX_set_elgamal_paramgen_bits(ctx, nbits) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_ElGamal, EVP_PKEY_OP_PARAMGEN, \
				EVP_PKEY_CTRL_ElGamal_PARAMGEN_BITS, nbits, NULL)

#define	EVP_PKEY_CTRL_ElGamal_PARAMGEN_BITS		(EVP_PKEY_ALG_CTRL + 1)
#define	EVP_PKEY_CTRL_ElGamal_PARAMGEN_Q_BITS	(EVP_PKEY_ALG_CTRL + 2)
#define	EVP_PKEY_CTRL_ElGamal_PARAMGEN_MD		(EVP_PKEY_ALG_CTRL + 3)

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_ElGamal_strings(void);

/* Error codes for the ElGamal functions. */

/* Function codes. */
#define ElGamal_F_D2I_ElGamal_SIG				 110
#define ElGamal_F_DO_ElGamal_PRINT				 104
#define ElGamal_F_ElGamalPARAMS_PRINT				 100
#define ElGamal_F_ElGamalPARAMS_PRINT_FP			 101
#define ElGamal_F_ElGamal_DO_SIGN				 112
#define ElGamal_F_ElGamal_DO_VERIFY				 113
#define ElGamal_F_ElGamal_NEW_METHOD				 103
#define ElGamal_F_ElGamal_PARAM_DECODE				 119
#define ElGamal_F_ElGamal_PRINT_FP				 105
#define ElGamal_F_ElGamal_PRIV_DECODE				 115
#define ElGamal_F_ElGamal_PRIV_ENCODE				 116
#define ElGamal_F_ElGamal_PUB_DECODE				 117
#define ElGamal_F_ElGamal_PUB_ENCODE				 118
#define ElGamal_F_ElGamal_SIGN					 106
#define ElGamal_F_ElGamal_SIGN_SETUP				 107
#define ElGamal_F_ElGamal_SIG_NEW				 109
#define ElGamal_F_ElGamal_VERIFY				 108
#define ElGamal_F_I2D_ElGamal_SIG				 111
#define ElGamal_F_OLD_ElGamal_PRIV_DECODE			 122
#define ElGamal_F_PKEY_ElGamal_CTRL				 120
#define ElGamal_F_PKEY_ElGamal_KEYGEN				 121
#define ElGamal_F_SIG_CB					 114

/* Reason codes. */
#define ElGamal_R_BAD_Q_VALUE				 102
#define ElGamal_R_BN_DECODE_ERROR				 108
#define ElGamal_R_BN_ERROR					 109
#define ElGamal_R_DATA_TOO_LARGE_FOR_KEY_SIZE		 100
#define ElGamal_R_DECODE_ERROR				 104
#define ElGamal_R_INVALID_DIGEST_TYPE			 106
#define ElGamal_R_MISSING_PARAMETERS			 101
#define ElGamal_R_MODULUS_TOO_LARGE				 103
#define ElGamal_R_NO_PARAMETERS_SET				 107
#define ElGamal_R_PARAMETER_ENCODING_ERROR			 105

#ifdef  __cplusplus
}
#endif
#endif
