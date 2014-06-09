/* crypto/elgamal/elgamal_vrf.c */
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

#include "cryptlib.h"
#include <openssl/elgamal.h>

int ElGamal_do_decrypt(unsigned char *msg, int *msglen, const ElGamal_SIG *cipher,
		  ElGamal *elgamal)
	{
	return elgamal->meth->elgamal_do_decrypt(msg, msglen, cipher, elgamal);
	}

int ElGamal_do_decrypt_ex(unsigned char *msg, int *msglen, const ElGamal_SIG_EX *cipher,
		  ElGamal *elgamal)
	{
	return elgamal->meth->elgamal_do_decrypt_ex(msg, msglen, cipher, elgamal);
	}


/* data has already been hashed (probably with SHA or SHA-1). */
/* returns
 *      1: correct signature
 *      0: incorrect signature
 *     -1: error
 */
int ElGamal_decrypt(int type, unsigned char *msg, int *msglen,
	     const unsigned char *cipher, int cipherlen, ElGamal *elgamal)
	{
	ElGamal_SIG *c;
	int ret=-1;

	c = ElGamal_SIG_new();
	if (c == NULL) return(ret);
	if (d2i_ElGamal_SIG(&c,&cipher,cipherlen) == NULL) goto err;
	ret=ElGamal_do_decrypt(msg,msglen,c,elgamal);
err:
	ElGamal_SIG_free(c);
	return(ret);
	}

int ElGamal_decrypt_ex(int type, unsigned char *msg, int *msglen,
		const unsigned char *cipher, int cipherlen, ElGamal *elgamal)
	{
	ElGamal_SIG_EX *c;
	int ret=-1;
	
	c = ElGamal_SIG_EX_new();
	if (c == NULL) return(ret);
	if (d2i_ElGamal_SIG_EX(&c,&cipher,cipherlen) == NULL) goto err;
	ret=ElGamal_do_decrypt_ex(msg,msglen,c,elgamal);
err:
	ElGamal_SIG_EX_free(c);
	return(ret);
	}
