/* crypto/elgamal/elgamaltest.c */
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
 *    the apps directory (application code) you must include an 
acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com
)"
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

/* Until the key-gen callbacks are modified to use newer prototypes, we allow
 * deprecated functions for openssl-internal code */

/*
 * This package is written by Vincent Huang (winscar@stu.xidian.edu.cn)
 * as a tool to do experiments. It can be freely used by anyone.
 * But it is not strong or secure enough to sustain comercial usage.
 * Hope you all happy to use this :-) */
 
#ifdef OPENSSL_NO_DEPRECATED
#undef OPENSSL_NO_DEPRECATED
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#include "../e_os.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>

#define K 100

#ifdef OPENSSL_NO_ElGamal
int main(int argc, char *argv[])
{
    printf("No ElGamal support\n");
    return(0);
}
#else
#include <openssl/elgamal.h>

#ifdef OPENSSL_SYS_WIN16
#define MS_CALLBACK     _far _loadds
#else
#define MS_CALLBACK
#endif

static int MS_CALLBACK elgamal_cb(int p, int n, BN_GENCB *arg);

static const unsigned char str[]="string to make the random number generator think it has entropy";

static BIO *bio_err=NULL;

int main(int argc, char **argv)
	{
	/* Declaration */
	BN_GENCB cb;
	ElGamal *elgamal=NULL;
	int i=0,counter,ret=0;
	unsigned long h;

	unsigned char msg[K][128];
	int msglen[K];
	unsigned char buf[128];
	int buflen=128;
	unsigned char txt[128];
	int txtlen=128;

	memset(buf,0x00,buflen);
	memset(txt,0x00,txtlen);

	unsigned char cipher[512];
	unsigned int cipherlen=512;

	BN_CTX *ctx=NULL;
	BIGNUM *before=NULL,*later=NULL;

	int clocks1,clocks2;

	/* Initialization */
	if (bio_err == NULL)	bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);

	CRYPTO_malloc_debug_init();
	CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

	ERR_load_crypto_strings();

	/* Parameters generation */
	BIO_printf(bio_err,"test generation of ElGamal parameters\n");

	BN_GENCB_set(&cb, elgamal_cb, bio_err);
	if(((elgamal = ElGamal_new()) == NULL) || !ElGamal_generate_parameters_ex(elgamal, 1024, NULL, &counter, &h, &cb))
		goto end;

	BIO_printf(bio_err,"\ncounter=%d h=%ld\n",counter,h);

	ElGamal_print(bio_err,elgamal,0);

	/* Messages generation */
	if ((ctx=BN_CTX_new()) == NULL)		goto end;
	if ((before = BN_new()) == NULL)	goto end;
	if ((later = BN_new()) == NULL)		goto end;
	for(i = 0; i < K; i++)
	{
		if (!BN_rand_range(before,elgamal->p))		goto end;
		if (!BN_mod_sqr(later,before,elgamal->p,ctx))	goto end;
		msglen[i] = BN_bn2bin(later,msg[i]);
	}

	/* Key generation */
	elgamal->flags |= ElGamal_FLAG_NO_EXP_CONSTTIME;		//elgamal->flags &= ~ElGamal_FLAG_NO_EXP_CONSTTIME;
	ElGamal_generate_key(elgamal);

	// Measure time
	clocks1 = clock();

	for(i = 0; i < K; i++)
	{
		ElGamal_encrypt(0, msg[i], msglen[i], cipher, &cipherlen, elgamal);
		ElGamal_reencrypt(0, buf, &buflen, cipher, cipherlen, elgamal);
		if (ElGamal_decrypt(0, txt, &txtlen, buf, buflen, elgamal) == 1)	ret=1;
		printf("%s", (memcmp(msg[i],txt,txtlen) == 0 ? "*" : "+"));

		memset(buf,0x00,128);
		memset(txt,0x00,128);
		memset(cipher,0x00,512);

		ElGamal_encrypt_ex(0, msg[i], 128, cipher, &cipherlen, elgamal);
		ElGamal_reencrypt_ex(0, buf, &buflen, cipher, cipherlen, elgamal);
		if (ElGamal_decrypt_ex(0, txt, &txtlen, buf, buflen, elgamal) == 1)  ret=1;
		printf("%s", (memcmp(msg[i],txt,txtlen) == 0 ? "*" : "-"));

		memset(buf,0x00,128);
		memset(txt,0x00,128);
		memset(cipher,0x00,512);
	}

	// Measure time
	clocks2 = clock();
	printf ("\n%f seconds used to encrypt!\n", ((float)clocks2-clocks1)/CLOCKS_PER_SEC);
end:
	if (!ret)		ERR_print_errors(bio_err);
	if (elgamal != NULL)	ElGamal_free(elgamal);

	if (ctx != NULL)	BN_CTX_free(ctx);
	if (before != NULL)	BN_free(before);
	if (later != NULL)	BN_free(later);
	
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_thread_state(NULL);
	ERR_free_strings();
	if (bio_err != NULL)
		{
		BIO_free(bio_err);
		bio_err = NULL;
		}
#ifdef OPENSSL_SYS_NETWARE
    if (!ret) printf("ERROR\n");
#endif
	EXIT(!ret);
	return(0);
	}

static int MS_CALLBACK elgamal_cb(int p, int n, BN_GENCB *arg)
	{
	char c='*';
	static int ok=0,num=0;

	if (p == 0) { c='.'; num++; };
	if (p == 1) c='+';
	if (p == 2) { c='*'; ok++; }
	if (p == 3) c='\n';
	BIO_write(arg->arg,&c,1);
	(void)BIO_flush(arg->arg);

	if (!ok && (p == 0) && (num > 1))
		{
		BIO_printf((BIO *)arg,"error in elgamaltest\n");
		return 0;
		}
	return 1;
	}
#endif
