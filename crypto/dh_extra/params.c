/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
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
 * Hudson (tjh@cryptsoft.com). */

#include <openssl/dh.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>

#include "../fipsmodule/bn/internal.h"


BIGNUM *BN_get_rfc3526_prime_1536(BIGNUM *ret) {
  static const BN_ULONG kPrime1536Data[] = {
      TOBN(0xffffffff, 0xffffffff), TOBN(0xf1746c08, 0xca237327),
      TOBN(0x670c354e, 0x4abc9804), TOBN(0x9ed52907, 0x7096966d),
      TOBN(0x1c62f356, 0x208552bb), TOBN(0x83655d23, 0xdca3ad96),
      TOBN(0x69163fa8, 0xfd24cf5f), TOBN(0x98da4836, 0x1c55d39a),
      TOBN(0xc2007cb8, 0xa163bf05), TOBN(0x49286651, 0xece45b3d),
      TOBN(0xae9f2411, 0x7c4b1fe6), TOBN(0xee386bfb, 0x5a899fa5),
      TOBN(0x0bff5cb6, 0xf406b7ed), TOBN(0xf44c42e9, 0xa637ed6b),
      TOBN(0xe485b576, 0x625e7ec6), TOBN(0x4fe1356d, 0x6d51c245),
      TOBN(0x302b0a6d, 0xf25f1437), TOBN(0xef9519b3, 0xcd3a431b),
      TOBN(0x514a0879, 0x8e3404dd), TOBN(0x020bbea6, 0x3b139b22),
      TOBN(0x29024e08, 0x8a67cc74), TOBN(0xc4c6628b, 0x80dc1cd1),
      TOBN(0xc90fdaa2, 0x2168c234), TOBN(0xffffffff, 0xffffffff),
  };

  static const BIGNUM kPrime1536BN = STATIC_BIGNUM(kPrime1536Data);

  BIGNUM *alloc = NULL;
  if (ret == NULL) {
    alloc = BN_new();
    if (alloc == NULL) {
      return NULL;
    }
    ret = alloc;
  }

  if (!BN_copy(ret, &kPrime1536BN)) {
    BN_free(alloc);
    return NULL;
  }

  return ret;
}

// dh_p_matches_rfc3526 returns one if |p| equals the RFC 3526 MODP prime
// produced by |getter| and zero otherwise.
static int dh_p_matches_rfc3526(const BIGNUM *p, BIGNUM *(*getter)(BIGNUM *)) {
  BIGNUM *candidate = getter(NULL);
  if (candidate == NULL) {
    return 0;
  }
  int equal = BN_cmp(p, candidate) == 0;
  BN_free(candidate);
  return equal;
}

// dh_p_matches_rfc7919 returns one if |p| equals the modulus of the RFC 7919
// ffdhe group produced by |getter| and zero otherwise.
static int dh_p_matches_rfc7919(const BIGNUM *p, DH *(*getter)(void)) {
  DH *dh = getter();
  if (dh == NULL) {
    return 0;
  }
  int equal = BN_cmp(p, DH_get0_p(dh)) == 0;
  DH_free(dh);
  return equal;
}

// dh_p_is_rfc3526 returns one if |p| is one of the RFC 3526 MODP primes. These
// groups define only (p, g=2); they do not define a subgroup order q.
static int dh_p_is_rfc3526(const BIGNUM *p) {
  switch (BN_num_bits(p)) {
    case 1536:
      return dh_p_matches_rfc3526(p, BN_get_rfc3526_prime_1536);
    case 2048:
      return dh_p_matches_rfc3526(p, BN_get_rfc3526_prime_2048);
    case 3072:
      return dh_p_matches_rfc3526(p, BN_get_rfc3526_prime_3072);
    case 4096:
      return dh_p_matches_rfc3526(p, BN_get_rfc3526_prime_4096);
    case 6144:
      return dh_p_matches_rfc3526(p, BN_get_rfc3526_prime_6144);
    case 8192:
      return dh_p_matches_rfc3526(p, BN_get_rfc3526_prime_8192);
    default:
      return 0;
  }
}

// dh_p_is_rfc7919 returns one if |p| is one of the RFC 7919 ffdhe primes. These
// groups define (p, g=2, q=(p-1)/2), and 2 is by construction a generator of
// the order-q subgroup.
static int dh_p_is_rfc7919(const BIGNUM *p) {
  switch (BN_num_bits(p)) {
    case 2048:
      return dh_p_matches_rfc7919(p, DH_get_rfc7919_2048);
    case 3072:
      return dh_p_matches_rfc7919(p, DH_get_rfc7919_3072);
    case 4096:
      return dh_p_matches_rfc7919(p, DH_get_rfc7919_4096);
    case 8192:
      return dh_p_matches_rfc7919(p, DH_get_rfc7919_8192);
    default:
      return 0;
  }
}

int dh_fast_path_from_safe_group(const DH *dh) {
  const BIGNUM *p = DH_get0_p(dh);
  const BIGNUM *g = DH_get0_g(dh);
  const BIGNUM *q = DH_get0_q(dh);

  // Every group we recognize (RFC 3526 MODP and RFC 7919 ffdhe) uses g = 2. A
  // different generator is not the named group, so let the full checks run.
  if (!BN_is_word(g, 2)) {
    return 0;
  }

  // p must match a known group prime. Both families are safe primes p = 2q+1,
  // so recognizing p means both p and (p-1)/2 are prime by definition; that is
  // what lets |DH_check| skip primality testing.
  const int is_rfc7919 = dh_p_is_rfc7919(p);
  if (!is_rfc7919 && !dh_p_is_rfc3526(p)) {
    return 0;
  }

  if (q != NULL) {
    // A subgroup order is only part of the RFC 7919 group definitions (where
    // q = (p-1)/2 and g = 2 lies in that subgroup). For an RFC 3526 prime a
    // supplied q is not something the group definition vouches for, so we do
    // not fast-path it.
    if (!is_rfc7919) {
      return 0;
    }
    // q must be exactly the group's subgroup order, (p-1)/2.
    BIGNUM *expected_q = BN_new();
    if (expected_q == NULL) {
      return 0;
    }
    int q_matches = BN_rshift1(expected_q, p) && BN_cmp(q, expected_q) == 0;
    BN_free(expected_q);
    if (!q_matches) {
      return 0;
    }
  }

  return 1;
}

int DH_generate_parameters_ex(DH *dh, int prime_bits, int generator,
                              BN_GENCB *cb) {
  // We generate DH parameters as follows
  // find a prime q which is prime_bits/2 bits long.
  // p=(2*q)+1 or (p-1)/2 = q
  // For this case, g is a generator if
  // g^((p-1)/q) mod p != 1 for values of q which are the factors of p-1.
  // Since the factors of p-1 are q and 2, we just need to check
  // g^2 mod p != 1 and g^q mod p != 1.
  //
  // Having said all that,
  // there is another special case method for the generators 2, 3 and 5.
  // for 2, p mod 24 == 11
  // for 3, p mod 12 == 5  <<<<< does not work for safe primes.
  // for 5, p mod 10 == 3 or 7
  //
  // Thanks to Phil Karn <karn@qualcomm.com> for the pointers about the
  // special generators and for answering some of my questions.
  //
  // I've implemented the second simple method :-).
  // Since DH should be using a safe prime (both p and q are prime),
  // this generator function can take a very very long time to run.

  // Actually there is no reason to insist that 'generator' be a generator.
  // It's just as OK (and in some sense better) to use a generator of the
  // order-q subgroup.

  BIGNUM *t1, *t2;
  int g, ok = 0;
  BN_CTX *ctx = NULL;

  ctx = BN_CTX_new();
  if (ctx == NULL) {
    goto err;
  }
  BN_CTX_start(ctx);
  t1 = BN_CTX_get(ctx);
  t2 = BN_CTX_get(ctx);
  if (t1 == NULL || t2 == NULL) {
    goto err;
  }

  // Make sure |dh| has the necessary elements
  if (dh->p == NULL) {
    dh->p = BN_new();
    if (dh->p == NULL) {
      goto err;
    }
  }
  if (dh->g == NULL) {
    dh->g = BN_new();
    if (dh->g == NULL) {
      goto err;
    }
  }

  if (generator <= 1) {
    OPENSSL_PUT_ERROR(DH, DH_R_BAD_GENERATOR);
    goto err;
  }
  if (generator == DH_GENERATOR_2) {
    if (!BN_set_word(t1, 24)) {
      goto err;
    }
    if (!BN_set_word(t2, 11)) {
      goto err;
    }
    g = 2;
  } else if (generator == DH_GENERATOR_5) {
    if (!BN_set_word(t1, 10)) {
      goto err;
    }
    if (!BN_set_word(t2, 3)) {
      goto err;
    }
    // BN_set_word(t3,7); just have to miss
    // out on these ones :-(
    g = 5;
  } else {
    // in the general case, don't worry if 'generator' is a
    // generator or not: since we are using safe primes,
    // it will generate either an order-q or an order-2q group,
    // which both is OK
    if (!BN_set_word(t1, 2)) {
      goto err;
    }
    if (!BN_set_word(t2, 1)) {
      goto err;
    }
    g = generator;
  }

  if (!BN_generate_prime_ex(dh->p, prime_bits, 1, t1, t2, cb)) {
    goto err;
  }
  if (!BN_GENCB_call(cb, 3, 0)) {
    goto err;
  }
  if (!BN_set_word(dh->g, g)) {
    goto err;
  }
  ok = 1;

err:
  if (!ok) {
    OPENSSL_PUT_ERROR(DH, ERR_R_BN_LIB);
  }

  if (ctx != NULL) {
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
  }
  return ok;
}

static int int_dh_bn_cpy(BIGNUM **dst, const BIGNUM *src) {
  BIGNUM *a = NULL;

  if (src) {
    a = BN_dup(src);
    if (!a) {
      return 0;
    }
  }

  BN_free(*dst);
  *dst = a;
  return 1;
}

static int int_dh_param_copy(DH *to, const DH *from, int is_x942) {
  if (is_x942 == -1) {
    is_x942 = !!from->q;
  }
  if (!int_dh_bn_cpy(&to->p, from->p) ||
      !int_dh_bn_cpy(&to->g, from->g)) {
    return 0;
  }

  if (!is_x942) {
    return 1;
  }

  if (!int_dh_bn_cpy(&to->q, from->q) ||
      !int_dh_bn_cpy(&to->j, from->j)) {
    return 0;
  }

  OPENSSL_free(to->seed);
  to->seed = NULL;
  to->seedlen = 0;

  if (from->seed) {
    to->seed = OPENSSL_memdup(from->seed, from->seedlen);
    if (!to->seed) {
      return 0;
    }
    to->seedlen = from->seedlen;
  }

  return 1;
}

DH *DHparams_dup(const DH *dh) {
  DH *ret = DH_new();
  if (!ret) {
    return NULL;
  }

  if (!int_dh_param_copy(ret, dh, -1)) {
    DH_free(ret);
    return NULL;
  }

  return ret;
}
<<<<<<< HEAD
=======

DH *DH_get_2048_256(void) { 
  static const BN_ULONG dh2048_256_p[] = {
    TOBN(0xDB094AE9, 0x1E1A1597), TOBN(0x693877FA, 0xD7EF09CA),
    TOBN(0x6116D227, 0x6E11715F), TOBN(0xA4B54330, 0xC198AF12),
    TOBN(0x75F26375, 0xD7014103), TOBN(0xC3A3960A, 0x54E710C3),
    TOBN(0xDED4010A, 0xBD0BE621), TOBN(0xC0B857F6, 0x89962856),
    TOBN(0xB3CA3F79, 0x71506026), TOBN(0x1CCACB83, 0xE6B486F6),
    TOBN(0x67E144E5, 0x14056425), TOBN(0xF6A167B5, 0xA41825D9),
    TOBN(0x3AD83477, 0x96524D8E), TOBN(0xF13C6D9A, 0x51BFA4AB),
    TOBN(0x2D525267, 0x35488A0E), TOBN(0xB63ACAE1, 0xCAA6B790),
    TOBN(0x4FDB70C5, 0x81B23F76), TOBN(0xBC39A0BF, 0x12307F5C),
    TOBN(0xB941F54E, 0xB1E59BB8), TOBN(0x6C5BFC11, 0xD45F9088),
    TOBN(0x22E0B1EF, 0x4275BF7B), TOBN(0x91F9E672, 0x5B4758C0),
    TOBN(0x5A8A9D30, 0x6BCF67ED), TOBN(0x209E0C64, 0x97517ABD),
    TOBN(0x3BF4296D, 0x830E9A7C), TOBN(0x16C3D911, 0x34096FAA),
    TOBN(0xFAF7DF45, 0x61B2AA30), TOBN(0xE00DF8F1, 0xD61957D4),
    TOBN(0x5D2CEED4, 0x435E3B00), TOBN(0x8CEEF608, 0x660DD0F2),
    TOBN(0xFFBBD19C, 0x65195999), TOBN(0x87A8E61D, 0xB4B6663C),
  };
  static const BN_ULONG dh2048_256_g[] = {
    TOBN(0x664B4C0F, 0x6CC41659), TOBN(0x5E2327CF, 0xEF98C582),
    TOBN(0xD647D148, 0xD4795451), TOBN(0x2F630784, 0x90F00EF8),
    TOBN(0x184B523D, 0x1DB246C3), TOBN(0xC7891428, 0xCDC67EB6),
    TOBN(0x7FD02837, 0x0DF92B52), TOBN(0xB3353BBB, 0x64E0EC37),
    TOBN(0xECD06E15, 0x57CD0915), TOBN(0xB7D2BBD2, 0xDF016199),
    TOBN(0xC8484B1E, 0x052588B9), TOBN(0xDB2A3B73, 0x13D3FE14),
    TOBN(0xD052B985, 0xD182EA0A), TOBN(0xA4BD1BFF, 0xE83B9C80),
    TOBN(0xDFC967C1, 0xFB3F2E55), TOBN(0xB5045AF2, 0x767164E1),
    TOBN(0x1D14348F, 0x6F2F9193), TOBN(0x64E67982, 0x428EBC83),
    TOBN(0x8AC376D2, 0x82D6ED38), TOBN(0x777DE62A, 0xAAB8A862),
    TOBN(0xDDF463E5, 0xE9EC144B), TOBN(0x0196F931, 0xC77A57F2),
    TOBN(0xA55AE313, 0x41000A65), TOBN(0x901228F8, 0xC28CBB18),
    TOBN(0xBC3773BF, 0x7E8C6F62), TOBN(0xBE3A6C1B, 0x0C6B47B1),
    TOBN(0xFF4FED4A, 0xAC0BB555), TOBN(0x10DBC150, 0x77BE463F),
    TOBN(0x07F4793A, 0x1A0BA125), TOBN(0x4CA7B18F, 0x21EF2054),
    TOBN(0x2E775066, 0x60EDBD48), TOBN(0x3FB32C9B, 0x73134D0B),
  };
  static const BN_ULONG dh2048_256_q[] = {
    TOBN(0xA308B0FE, 0x64F5FBD3), TOBN(0x99B1A47D, 0x1EB3750B),
    TOBN(0xB4479976, 0x40129DA2), TOBN(0x8CF83642, 0xA709A097),
  };

  struct standard_parameters {
    BIGNUM p, q, g;
  };

  static const struct standard_parameters dh2048_256 = {
    STATIC_BIGNUM(dh2048_256_p),
    STATIC_BIGNUM(dh2048_256_q),
    STATIC_BIGNUM(dh2048_256_g),
  };

  DH *dh = DH_new();
  if (!dh) {
    return NULL;
  }

  dh->p = BN_dup(&dh2048_256.p);
  dh->q = BN_dup(&dh2048_256.q);
  dh->g = BN_dup(&dh2048_256.g);
  if (!dh->p || !dh->q || !dh->g) {
    DH_free(dh);
    return NULL;
  }

  return dh;
}

DH *DH_get_rfc7919_3072(void) {
  // This is the prime from https://tools.ietf.org/html/rfc7919#appendix-A.2,
  static const BN_ULONG kFFDHE3072Data[] = {
    TOBN(0xffffffff, 0xffffffff), TOBN(0x25e41d2b, 0x66c62e37),
    TOBN(0x3c1b20ee, 0x3fd59d7c), TOBN(0x0abcd06b, 0xfa53ddef),
    TOBN(0x1dbf9a42, 0xd5c4484e), TOBN(0xabc52197, 0x9b0deada),
    TOBN(0xe86d2bc5, 0x22363a0d), TOBN(0x5cae82ab, 0x9c9df69e),
    TOBN(0x64f2e21e, 0x71f54bff), TOBN(0xf4fd4452, 0xe2d74dd3),
    TOBN(0xb4130c93, 0xbc437944), TOBN(0xaefe1309, 0x85139270),
    TOBN(0x598cb0fa, 0xc186d91c), TOBN(0x7ad91d26, 0x91f7f7ee),
    TOBN(0x61b46fc9, 0xd6e6c907), TOBN(0xbc34f4de, 0xf99c0238),
    TOBN(0xde355b3b, 0x6519035b), TOBN(0x886b4238, 0x611fcfdc),
    TOBN(0xc6f34a26, 0xc1b2effa), TOBN(0xc58ef183, 0x7d1683b2),
    TOBN(0x3bb5fcbc, 0x2ec22005), TOBN(0xc3fe3b1b, 0x4c6fad73),
    TOBN(0x8e4f1232, 0xeef28183), TOBN(0x9172fe9c, 0xe98583ff),
    TOBN(0xc03404cd, 0x28342f61), TOBN(0x9e02fce1, 0xcdf7e2ec),
    TOBN(0x0b07a7c8, 0xee0a6d70), TOBN(0xae56ede7, 0x6372bb19),
    TOBN(0x1d4f42a3, 0xde394df4), TOBN(0xb96adab7, 0x60d7f468),
    TOBN(0xd108a94b, 0xb2c8e3fb), TOBN(0xbc0ab182, 0xb324fb61),
    TOBN(0x30acca4f, 0x483a797a), TOBN(0x1df158a1, 0x36ade735),
    TOBN(0xe2a689da, 0xf3efe872), TOBN(0x984f0c70, 0xe0e68b77),
    TOBN(0xb557135e, 0x7f57c935), TOBN(0x85636555, 0x3ded1af3),
    TOBN(0x2433f51f, 0x5f066ed0), TOBN(0xd3df1ed5, 0xd5fd6561),
    TOBN(0xf681b202, 0xaec4617a), TOBN(0x7d2fe363, 0x630c75d8),
    TOBN(0xcc939dce, 0x249b3ef9), TOBN(0xa9e13641, 0x146433fb),
    TOBN(0xd8b9c583, 0xce2d3695), TOBN(0xafdc5620, 0x273d3cf1),
    TOBN(0xadf85458, 0xa2bb4a9a), TOBN(0xffffffff, 0xffffffff)};

  return dh_calculate_rfc7919_from_p(kFFDHE3072Data,
                                     OPENSSL_ARRAY_SIZE(kFFDHE3072Data));
}

DH *DH_get_rfc7919_4096(void) {
    // This is the prime from https://tools.ietf.org/html/rfc7919#appendix-A.3,
    static const BN_ULONG kFFDHE4096Data[] = {
      TOBN(0xFFFFFFFF, 0xFFFFFFFF),TOBN(0xC68A007E, 0x5E655F6A),
      TOBN(0x4DB5A851, 0xF44182E1),TOBN(0x8EC9B55A, 0x7F88A46B),
      TOBN(0x0A8291CD, 0xCEC97DCF),TOBN(0x2A4ECEA9, 0xF98D0ACC),
      TOBN(0x1A1DB93D, 0x7140003C),TOBN(0x092999A3, 0x33CB8B7A),
      TOBN(0x6DC778F9, 0x71AD0038),TOBN(0xA907600A, 0x918130C4),
      TOBN(0xED6A1E01, 0x2D9E6832),TOBN(0x7135C886, 0xEFB4318A),
      TOBN(0x87F55BA5, 0x7E31CC7A),TOBN(0x7763CF1D, 0x55034004),
      TOBN(0xAC7D5F42, 0xD69F6D18),TOBN(0x7930E9E4, 0xE58857B6),
      TOBN(0x6E6F52C3, 0x164DF4FB),TOBN(0x25E41D2B, 0x669E1EF1),
      TOBN(0x3C1B20EE, 0x3FD59D7C),TOBN(0x0ABCD06B, 0xFA53DDEF),
      TOBN(0x1DBF9A42, 0xD5C4484E),TOBN(0xABC52197, 0x9B0DEADA),
      TOBN(0xE86D2BC5, 0x22363A0D),TOBN(0x5CAE82AB, 0x9C9DF69E),
      TOBN(0x64F2E21E, 0x71F54BFF),TOBN(0xF4FD4452, 0xE2D74DD3),
      TOBN(0xB4130C93, 0xBC437944),TOBN(0xAEFE1309, 0x85139270),
      TOBN(0x598CB0FA, 0xC186D91C),TOBN(0x7AD91D26, 0x91F7F7EE),
      TOBN(0x61B46FC9, 0xD6E6C907),TOBN(0xBC34F4DE, 0xF99C0238),
      TOBN(0xDE355B3B, 0x6519035B),TOBN(0x886B4238, 0x611FCFDC),
      TOBN(0xC6F34A26, 0xC1B2EFFA),TOBN(0xC58EF183, 0x7D1683B2),
      TOBN(0x3BB5FCBC, 0x2EC22005),TOBN(0xC3FE3B1B, 0x4C6FAD73),
      TOBN(0x8E4F1232, 0xEEF28183),TOBN(0x9172FE9C, 0xE98583FF),
      TOBN(0xC03404CD, 0x28342F61),TOBN(0x9E02FCE1, 0xCDF7E2EC),
      TOBN(0x0B07A7C8, 0xEE0A6D70),TOBN(0xAE56EDE7, 0x6372BB19),
      TOBN(0x1D4F42A3, 0xDE394DF4),TOBN(0xB96ADAB7, 0x60D7F468),
      TOBN(0xD108A94B, 0xB2C8E3FB),TOBN(0xBC0AB182, 0xB324FB61),
      TOBN(0x30ACCA4F, 0x483A797A),TOBN(0x1DF158A1, 0x36ADE735),
      TOBN(0xE2A689DA, 0xF3EFE872),TOBN(0x984F0C70, 0xE0E68B77),
      TOBN(0xB557135E, 0x7F57C935),TOBN(0x85636555, 0x3DED1AF3),
      TOBN(0x2433F51F, 0x5F066ED0),TOBN(0xD3DF1ED5, 0xD5FD6561),
      TOBN(0xF681B202, 0xAEC4617A),TOBN(0x7D2FE363, 0x630C75D8),
      TOBN(0xCC939DCE, 0x249B3EF9),TOBN(0xA9E13641, 0x146433FB),
      TOBN(0xD8B9C583, 0xCE2D3695),TOBN(0xAFDC5620, 0x273D3CF1),
      TOBN(0xADF85458, 0xA2BB4A9A),TOBN(0xFFFFFFFF, 0xFFFFFFFF)
    };

    return dh_calculate_rfc7919_from_p(kFFDHE4096Data,
                                       OPENSSL_ARRAY_SIZE(kFFDHE4096Data));
}

DH *DH_get_rfc7919_8192(void) {
  // This is the prime from https://tools.ietf.org/html/rfc7919#appendix-A.4,
  static const BN_ULONG kFFDHE8192Data[] = {
    TOBN(0xffffffff, 0xffffffff), TOBN(0xd68c8bb7, 0xc5c6424c),
    TOBN(0x011e2a94, 0x838ff88c), TOBN(0x0822e506, 0xa9f4614e),
    TOBN(0x97d11d49, 0xf7a8443d), TOBN(0xa6bbfde5, 0x30677f0d),
    TOBN(0x2f741ef8, 0xc1fe86fe), TOBN(0xfafabe1c, 0x5d71a87e),
    TOBN(0xded2fbab, 0xfbe58a30), TOBN(0xb6855dfe, 0x72b0a66e),
    TOBN(0x1efc8ce0, 0xba8a4fe8), TOBN(0x83f81d4a, 0x3f2fa457),
    TOBN(0xa1fe3075, 0xa577e231), TOBN(0xd5b80194, 0x88d9c0a0),
    TOBN(0x624816cd, 0xad9a95f9), TOBN(0x99e9e316, 0x50c1217b),
    TOBN(0x51aa691e, 0x0e423cfc), TOBN(0x1c217e6c, 0x3826e52c),
    TOBN(0x51a8a931, 0x09703fee), TOBN(0xbb709987, 0x6a460e74),
    TOBN(0x541fc68c, 0x9c86b022), TOBN(0x59160cc0, 0x46fd8251),
    TOBN(0x2846c0ba, 0x35c35f5c), TOBN(0x54504ac7, 0x8b758282),
    TOBN(0x29388839, 0xd2af05e4), TOBN(0xcb2c0f1c, 0xc01bd702),
    TOBN(0x555b2f74, 0x7c932665), TOBN(0x86b63142, 0xa3ab8829),
    TOBN(0x0b8cc3bd, 0xf64b10ef), TOBN(0x687feb69, 0xedd1cc5e),
    TOBN(0xfdb23fce, 0xc9509d43), TOBN(0x1e425a31, 0xd951ae64),
    TOBN(0x36ad004c, 0xf600c838), TOBN(0xa40e329c, 0xcff46aaa),
    TOBN(0xa41d570d, 0x7938dad4), TOBN(0x62a69526, 0xd43161c1),
    TOBN(0x3fdd4a8e, 0x9adb1e69), TOBN(0x5b3b71f9, 0xdc6b80d6),
    TOBN(0xec9d1810, 0xc6272b04), TOBN(0x8ccf2dd5, 0xcacef403),
    TOBN(0xe49f5235, 0xc95b9117), TOBN(0x505dc82d, 0xb854338a),
    TOBN(0x62292c31, 0x1562a846), TOBN(0xd72b0374, 0x6ae77f5e),
    TOBN(0xf9c9091b, 0x462d538c), TOBN(0x0ae8db58, 0x47a67cbe),
    TOBN(0xb3a739c1, 0x22611682), TOBN(0xeeaac023, 0x2a281bf6),
    TOBN(0x94c6651e, 0x77caf992), TOBN(0x763e4e4b, 0x94b2bbc1),
    TOBN(0x587e38da, 0x0077d9b4), TOBN(0x7fb29f8c, 0x183023c3),
    TOBN(0x0abec1ff, 0xf9e3a26e), TOBN(0xa00ef092, 0x350511e3),
    TOBN(0xb855322e, 0xdb6340d8), TOBN(0xa52471f7, 0xa9a96910),
    TOBN(0x388147fb, 0x4cfdb477), TOBN(0x9b1f5c3e, 0x4e46041f),
    TOBN(0xcdad0657, 0xfccfec71), TOBN(0xb38e8c33, 0x4c701c3a),
    TOBN(0x917bdd64, 0xb1c0fd4c), TOBN(0x3bb45432, 0x9b7624c8),
    TOBN(0x23ba4442, 0xcaf53ea6), TOBN(0x4e677d2c, 0x38532a3a),
    TOBN(0x0bfd64b6, 0x45036c7a), TOBN(0xc68a007e, 0x5e0dd902),
    TOBN(0x4db5a851, 0xf44182e1), TOBN(0x8ec9b55a, 0x7f88a46b),
    TOBN(0x0a8291cd, 0xcec97dcf), TOBN(0x2a4ecea9, 0xf98d0acc),
    TOBN(0x1a1db93d, 0x7140003c), TOBN(0x092999a3, 0x33cb8b7a),
    TOBN(0x6dc778f9, 0x71ad0038), TOBN(0xa907600a, 0x918130c4),
    TOBN(0xed6a1e01, 0x2d9e6832), TOBN(0x7135c886, 0xefb4318a),
    TOBN(0x87f55ba5, 0x7e31cc7a), TOBN(0x7763cf1d, 0x55034004),
    TOBN(0xac7d5f42, 0xd69f6d18), TOBN(0x7930e9e4, 0xe58857b6),
    TOBN(0x6e6f52c3, 0x164df4fb), TOBN(0x25e41d2b, 0x669e1ef1),
    TOBN(0x3c1b20ee, 0x3fd59d7c), TOBN(0x0abcd06b, 0xfa53ddef),
    TOBN(0x1dbf9a42, 0xd5c4484e), TOBN(0xabc52197, 0x9b0deada),
    TOBN(0xe86d2bc5, 0x22363a0d), TOBN(0x5cae82ab, 0x9c9df69e),
    TOBN(0x64f2e21e, 0x71f54bff), TOBN(0xf4fd4452, 0xe2d74dd3),
    TOBN(0xb4130c93, 0xbc437944), TOBN(0xaefe1309, 0x85139270),
    TOBN(0x598cb0fa, 0xc186d91c), TOBN(0x7ad91d26, 0x91f7f7ee),
    TOBN(0x61b46fc9, 0xd6e6c907), TOBN(0xbc34f4de, 0xf99c0238),
    TOBN(0xde355b3b, 0x6519035b), TOBN(0x886b4238, 0x611fcfdc),
    TOBN(0xc6f34a26, 0xc1b2effa), TOBN(0xc58ef183, 0x7d1683b2),
    TOBN(0x3bb5fcbc, 0x2ec22005), TOBN(0xc3fe3b1b, 0x4c6fad73),
    TOBN(0x8e4f1232, 0xeef28183), TOBN(0x9172fe9c, 0xe98583ff),
    TOBN(0xc03404cd, 0x28342f61), TOBN(0x9e02fce1, 0xcdf7e2ec),
    TOBN(0x0b07a7c8, 0xee0a6d70), TOBN(0xae56ede7, 0x6372bb19),
    TOBN(0x1d4f42a3, 0xde394df4), TOBN(0xb96adab7, 0x60d7f468),
    TOBN(0xd108a94b, 0xb2c8e3fb), TOBN(0xbc0ab182, 0xb324fb61),
    TOBN(0x30acca4f, 0x483a797a), TOBN(0x1df158a1, 0x36ade735),
    TOBN(0xe2a689da, 0xf3efe872), TOBN(0x984f0c70, 0xe0e68b77),
    TOBN(0xb557135e, 0x7f57c935), TOBN(0x85636555, 0x3ded1af3),
    TOBN(0x2433f51f, 0x5f066ed0), TOBN(0xd3df1ed5, 0xd5fd6561),
    TOBN(0xf681b202, 0xaec4617a), TOBN(0x7d2fe363, 0x630c75d8),
    TOBN(0xcc939dce, 0x249b3ef9), TOBN(0xa9e13641, 0x146433fb),
    TOBN(0xd8b9c583, 0xce2d3695), TOBN(0xafdc5620, 0x273d3cf1),
    TOBN(0xadf85458, 0xa2bb4a9a), TOBN(0xffffffff, 0xffffffff)
  };

  return dh_calculate_rfc7919_from_p(kFFDHE8192Data,
                                     OPENSSL_ARRAY_SIZE(kFFDHE8192Data));
}

DH *DH_new_by_nid(int nid) {
  switch (nid) {
    case NID_ffdhe2048:
      return DH_get_rfc7919_2048();
    case NID_ffdhe3072:
      return DH_get_rfc7919_3072();
    case NID_ffdhe4096:
      return DH_get_rfc7919_4096();
    case NID_ffdhe8192:
      return DH_get_rfc7919_8192();
    default:
      OPENSSL_PUT_ERROR(DH, DH_R_INVALID_NID);
      return NULL;
  }
}
>>>>>>> ac3aee310 (Recognise known safe DH groups/primes and short-circuit Diffie-Hellman test (#3337))
