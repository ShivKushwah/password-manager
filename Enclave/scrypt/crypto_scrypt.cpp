/*-
 * Copyright 2009 Colin Percival
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
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
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */
//#include "scrypt_platform.h"

#include "Enclave_t.h"
#include <sys/types.h>
//#include <sys/mman.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>



//#include "cpusupport.h"
#include "sha256.h"
//#include "warnp.h"

#include "crypto_scrypt_smix.h"
//#include "crypto_scrypt_smix_sse2.h"

#include "crypto_scrypt.h"

static void (*smix_func)(uint8_t *, size_t, uint64_t, void *, void *) = NULL;

/**
 * _crypto_scrypt(passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen, smix):
 * Perform the requested scrypt computation, using ${smix} as the smix routine.
 */
static int
_crypto_scrypt(const uint8_t * passwd, size_t passwdlen,
    const uint8_t * salt, size_t saltlen, uint64_t N, uint32_t _r, uint32_t _p,
    uint8_t * buf, size_t buflen,
    void (*smix)(uint8_t *, size_t, uint64_t, void *, void *))
{
	void * B0, * V0, * XY0;
	uint8_t * B;
	uint32_t * V;
	uint32_t * XY;
	size_t r = _r, p = _p;
	uint32_t i;


	/* Allocate memory. */

	B = (uint8_t *)(B0);

	XY = (uint32_t *)(XY0);

	V = (uint32_t *)(V0);



	/* 1: (B_0 ... B_{p-1}) <-- PBKDF2(P, S, 1, p * MFLen) */
	PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, 1, B, p * 128 * r);

	/* 2: for i = 0 to p - 1 do */
	for (i = 0; i < p; i++) {
		/* 3: B_i <-- MF(B_i, N) */
		(smix)(&B[i * 128 * r], r, N, V, XY);
	}

	/* 5: DK <-- PBKDF2(P, B, 1, dkLen) */
	PBKDF2_SHA256(passwd, passwdlen, B, p * 128 * r, 1, buf, buflen);

	
	return (0);


}



int
do_something()
{
    ocall_print("doing something.");
}


/**
 * crypto_scrypt(passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen):
 * Compute scrypt(passwd[0 .. passwdlen - 1], salt[0 .. saltlen - 1], N, r,
 * p, buflen) and write the result into buf.  The parameters r, p, and buflen
 * must satisfy r * p < 2^30 and buflen <= (2^32 - 1) * 32.  The parameter N
 * must be a power of 2 greater than 1.
 *
 * Return 0 on success; or -1 on error.
 */
int
crypto_scrypt(const uint8_t * passwd, size_t passwdlen,
    const uint8_t * salt, size_t saltlen, uint64_t N, uint32_t _r, uint32_t _p,
    uint8_t * buf, size_t buflen)
{
	return (_crypto_scrypt(passwd, passwdlen, salt, saltlen, N, _r, _p,
	    buf, buflen, crypto_scrypt_smix));
}
