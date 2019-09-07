/*-
 * Copyright 2009 Colin Percival, 2011 ArtForz, 2013 Neisklar,
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

#include "quark.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_luffa.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"
#include "sha3/sph_hamsi.h"
#include "sha3/sph_fugue.h"
#include "sha3/sph_shabal.h"
#include "sha3/sph_whirlpool.h"
#include "sha3/sph_sha2.h"
#include "sha3/sph_haval.h"

static __inline uint32_t
be32dec(const void *pp)
{
    const uint8_t *p = (uint8_t const *)pp;

    return ((uint32_t)(p[3]) + ((uint32_t)(p[2]) << 8) +
            ((uint32_t)(p[1]) << 16) + ((uint32_t)(p[0]) << 24));
}

static __inline void
be32enc(void *pp, uint32_t x)
{
    uint8_t * p = (uint8_t *)pp;

    p[3] = x & 0xff;
    p[2] = (x >> 8) & 0xff;
    p[1] = (x >> 16) & 0xff;
    p[0] = (x >> 24) & 0xff;
}

static __inline uint32_t
le32dec(const void *pp)
{
    const uint8_t *p = (uint8_t const *)pp;

    return ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) +
            ((uint32_t)(p[2]) << 16) + ((uint32_t)(p[3]) << 24));
}

static __inline void
le32enc(void *pp, uint32_t x)
{
    uint8_t * p = (uint8_t *)pp;

    p[0] = x & 0xff;
    p[1] = (x >> 8) & 0xff;
    p[2] = (x >> 16) & 0xff;
    p[3] = (x >> 24) & 0xff;
}

/*
 * Encode a length len/4 vector of (uint32_t) into a length len vector of
 * (unsigned char) in big-endian form.  Assumes len is a multiple of 4.
 */
static void
be32enc_vect(unsigned char *dst, const uint32_t *src, size_t len)
{
    size_t i;

    for (i = 0; i < len / 4; i++)
        be32enc(dst + i * 4, src[i]);
}

/*
 * Decode a big-endian length len vector of (unsigned char) into a length
 * len/4 vector of (uint32_t).  Assumes len is a multiple of 4.
 */
static void
be32dec_vect(uint32_t *dst, const unsigned char *src, size_t len)
{
    size_t i;

    for (i = 0; i < len / 4; i++)
        dst[i] = be32dec(src + i * 4);
}

void quark_hash(const char* input, char* output)
{
    sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_groestl512_context   ctx_groestl;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_skein512_context     ctx_skein;
    static unsigned char pblank[1];

    uint32_t mask = 8;
    uint32_t zero = 0;

    uint32_t hashA[16], hashB[16];



    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, input, 80);
    sph_blake512_close (&ctx_blake, hashA);	 //0


    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, hashA, 64);    //0
    sph_bmw512_close(&ctx_bmw, hashB);   //1


    if ((hashB[0] & mask) != zero)   //1
    {
        sph_groestl512_init(&ctx_groestl);
        sph_groestl512 (&ctx_groestl, hashB, 64); //1
        sph_groestl512_close(&ctx_groestl, hashA); //2
    }
    else
    {
        sph_skein512_init(&ctx_skein);
        sph_skein512 (&ctx_skein, hashB, 64); //1
        sph_skein512_close(&ctx_skein, hashA); //2
    }


    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, hashA, 64); //2
    sph_groestl512_close(&ctx_groestl, hashB); //3

    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, hashB, 64); //3
    sph_jh512_close(&ctx_jh, hashA); //4

    if ((hashA[0] & mask) != zero) //4
    {
        sph_blake512_init(&ctx_blake);
        sph_blake512 (&ctx_blake, hashA, 64); //
        sph_blake512_close(&ctx_blake, hashB); //5
    }
    else
    {
        sph_bmw512_init(&ctx_bmw);
        sph_bmw512 (&ctx_bmw, hashA, 64); //4
        sph_bmw512_close(&ctx_bmw, hashB);   //5
    }

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak,hashB, 64); //5
    sph_keccak512_close(&ctx_keccak, hashA); //6

    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, hashA, 64); //6
    sph_skein512_close(&ctx_skein, hashB); //7

    if ((hashB[0] & mask) != zero) //7
    {
        sph_keccak512_init(&ctx_keccak);
        sph_keccak512 (&ctx_keccak, hashB, 64); //
        sph_keccak512_close(&ctx_keccak, hashA); //8
    }
    else
    {
        sph_jh512_init(&ctx_jh);
        sph_jh512 (&ctx_jh, hashB, 64); //7
        sph_jh512_close(&ctx_jh, hashA); //8
    }



    memcpy(output, hashA, 32);

}
void xevan_hash(const char* input, char* output)
{
    sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_groestl512_context   ctx_groestl;
    sph_skein512_context     ctx_skein;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    
    sph_luffa512_context        ctx_luffa1;
    sph_cubehash512_context        ctx_cubehash1;
    sph_shavite512_context        ctx_shavite1;
    sph_simd512_context        ctx_simd1;
    sph_echo512_context        ctx_echo1;
    
    sph_hamsi512_context        ctx_hamsi;
    sph_fugue512_context        ctx_fugue;
    sph_shabal512_context        ctx_shabal;
    sph_whirlpool_context        ctx_whirlpool;
    sph_sha512_context            ctx_sha2;
    
    sph_haval256_5_context        ctx_haval;
    
    
    
    uint32_t hashA[32], hashB[32];
    memset(hashA , 0, 128);
    memset(hashB , 0, 128);
    
    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, input, 80);
    sph_blake512_close (&ctx_blake, hashA);
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, hashA, 128);
    sph_bmw512_close(&ctx_bmw, hashB);
    
    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, hashB, 128);
    sph_groestl512_close(&ctx_groestl, hashA);
    
    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, hashA, 128);
    sph_skein512_close (&ctx_skein, hashB);
    
    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, hashB, 128);
    sph_jh512_close(&ctx_jh, hashA);
    
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, hashA, 128);
    sph_keccak512_close(&ctx_keccak, hashB);
    
    sph_luffa512_init (&ctx_luffa1);
    sph_luffa512 (&ctx_luffa1, hashB, 128);
    sph_luffa512_close (&ctx_luffa1, hashA);
    
    sph_cubehash512_init (&ctx_cubehash1);
    sph_cubehash512 (&ctx_cubehash1, hashA, 128);
    sph_cubehash512_close(&ctx_cubehash1, hashB);
    
    sph_shavite512_init (&ctx_shavite1);
    sph_shavite512 (&ctx_shavite1, hashB, 128);
    sph_shavite512_close(&ctx_shavite1, hashA);
    
    sph_simd512_init (&ctx_simd1);
    sph_simd512 (&ctx_simd1, hashA, 128);
    sph_simd512_close(&ctx_simd1, hashB);
    
    sph_echo512_init (&ctx_echo1);
    sph_echo512 (&ctx_echo1, hashB, 128);
    sph_echo512_close(&ctx_echo1, hashA);
    
    
    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512 (&ctx_hamsi, hashA, 128);
    sph_hamsi512_close(&ctx_hamsi, hashB);
    
    sph_fugue512_init(&ctx_fugue);
    sph_fugue512 (&ctx_fugue, hashB, 128);
    sph_fugue512_close(&ctx_fugue, hashA);
    
    sph_shabal512_init(&ctx_shabal);
    sph_shabal512 (&ctx_shabal, hashA, 128);
    sph_shabal512_close(&ctx_shabal, hashB);
    
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool (&ctx_whirlpool, hashB, 128);
    sph_whirlpool_close(&ctx_whirlpool, hashA);
    
    sph_sha512_init(&ctx_sha2);
    sph_sha512 (&ctx_sha2, hashA, 128);
    sph_sha512_close(&ctx_sha2, hashB);
    
    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5 (&ctx_haval, hashB, 128);
    sph_haval256_5_close(&ctx_haval, hashA);
    memset(&hashA[8], 0, 128 - 32);
    
    
    ///  Part2
    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, hashA, 128);
    sph_blake512_close(&ctx_blake, hashB);
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, hashB, 128);
    sph_bmw512_close(&ctx_bmw, hashA);
    
    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, hashA, 128);
    sph_groestl512_close(&ctx_groestl, hashB);
    
    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, hashB, 128);
    sph_skein512_close(&ctx_skein, hashA);
    
    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, hashA, 128);
    sph_jh512_close(&ctx_jh, hashB);
    
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, hashB, 128);
    sph_keccak512_close(&ctx_keccak, hashA);
    
    sph_luffa512_init(&ctx_luffa1);
    sph_luffa512 (&ctx_luffa1, hashA, 128);
    sph_luffa512_close(&ctx_luffa1, hashB);
    
    sph_cubehash512_init(&ctx_cubehash1);
    sph_cubehash512 (&ctx_cubehash1, hashB, 128);
    sph_cubehash512_close(&ctx_cubehash1, hashA);
    
    sph_shavite512_init(&ctx_shavite1);
    sph_shavite512(&ctx_shavite1, hashA, 128);
    sph_shavite512_close(&ctx_shavite1, hashB);
    
    sph_simd512_init(&ctx_simd1);
    sph_simd512 (&ctx_simd1, hashB, 128);
    sph_simd512_close(&ctx_simd1, hashA);
    
    sph_echo512_init(&ctx_echo1);
    sph_echo512 (&ctx_echo1, hashA, 128);
    sph_echo512_close(&ctx_echo1, hashB);
    
    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512 (&ctx_hamsi, hashB, 128);
    sph_hamsi512_close(&ctx_hamsi, hashA);
    
    sph_fugue512_init(&ctx_fugue);
    sph_fugue512 (&ctx_fugue, hashA, 128);
    sph_fugue512_close(&ctx_fugue, hashB);
    
    sph_shabal512_init(&ctx_shabal);
    sph_shabal512 (&ctx_shabal, hashB, 128);
    sph_shabal512_close(&ctx_shabal, hashA);
    
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool (&ctx_whirlpool, hashA, 128);
    sph_whirlpool_close(&ctx_whirlpool, hashB);
    
    sph_sha512_init(&ctx_sha2);
    sph_sha512 (&ctx_sha2, hashB, 128);
    sph_sha512_close(&ctx_sha2, hashA);
    
    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5 (&ctx_haval, hashA, 128);
    sph_haval256_5_close(&ctx_haval, hashB);
    
    
    memcpy(output, hashB, 32);
    
}
