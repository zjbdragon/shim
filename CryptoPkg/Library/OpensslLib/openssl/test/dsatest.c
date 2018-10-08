/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "../e_os.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>

#ifdef OPENSSL_NO_DSA
int main(int argc, char *argv[])
{
    printf("No DSA support\n");
    return (0);
}
#else
# include <openssl/dsa.h>

static int dsa_cb(int p, int n, BN_GENCB *arg);

static unsigned char seed[20] = {
    0x02, 0x47, 0x11, 0x92, 0x11, 0x88, 0xC8, 0xFB, 0xAF, 0x48, 0x4C, 0x62,
    0xDF, 0xA5, 0xBE, 0xA0, 0xA4, 0x3C, 0x56, 0xE3,
};

static unsigned char out_p[] = {
    0xAC, 0xCB, 0x1E, 0x63, 0x60, 0x69, 0x0C, 0xFB, 0x06, 0x19, 0x68, 0x3E,
    0xA5, 0x01, 0x5A, 0xA2, 0x15, 0x5C, 0xE2, 0x99, 0x2D, 0xD5, 0x30, 0x99,
    0x7E, 0x5F, 0x8D, 0xE2, 0xF7, 0xC6, 0x2E, 0x8D, 0xA3, 0x9F, 0x58, 0xAD,
    0xD6, 0xA9, 0x7D, 0x0E, 0x0D, 0x95, 0x53, 0xA6, 0x71, 0x3A, 0xDE, 0xAB,
    0xAC, 0xE9, 0xF4, 0x36, 0x55, 0x9E, 0xB9, 0xD6, 0x93, 0xBF, 0xF3, 0x18,
    0x1C, 0x14, 0x7B, 0xA5, 0x42, 0x2E, 0xCD, 0x00, 0xEB, 0x35, 0x3B, 0x1B,
    0xA8, 0x51, 0xBB, 0xE1, 0x58, 0x42, 0x85, 0x84, 0x22, 0xA7, 0x97, 0x5E,
    0x99, 0x6F, 0x38, 0x20, 0xBD, 0x9D, 0xB6, 0xD9, 0x33, 0x37, 0x2A, 0xFD,
    0xBB, 0xD4, 0xBC, 0x0C, 0x2A, 0x67, 0xCB, 0x9F, 0xBB, 0xDF, 0xF9, 0x93,
    0xAA, 0xD6, 0xF0, 0xD6, 0x95, 0x0B, 0x5D, 0x65, 0x14, 0xD0, 0x18, 0x9D,
    0xC6, 0xAF, 0xF0, 0xC6, 0x37, 0x7C, 0xF3, 0x5F,
};

static unsigned char out_q[] = {
    0xE3, 0x8E, 0x5E, 0x6D, 0xBF, 0x2B, 0x79, 0xF8, 0xC5, 0x4B, 0x89, 0x8B,
    0xBA, 0x2D, 0x91, 0xC3, 0x6C, 0x80, 0xAC, 0x87,
};

static unsigned char out_g[] = {
    0x42, 0x4A, 0x04, 0x4E, 0x79, 0xB4, 0x99, 0x7F, 0xFD, 0x58, 0x36, 0x2C,
    0x1B, 0x5F, 0x18, 0x7E, 0x0D, 0xCC, 0xAB, 0x81, 0xC9, 0x5D, 0x10, 0xCE,
    0x4E, 0x80, 0x7E, 0x58, 0xB4, 0x34, 0x3F, 0xA7, 0x45, 0xC7, 0xAA, 0x36,
    0x24, 0x42, 0xA9, 0x3B, 0xE8, 0x0E, 0x04, 0x02, 0x2D, 0xFB, 0xA6, 0x13,
    0xB9, 0xB5, 0x15, 0xA5, 0x56, 0x07, 0x35, 0xE4, 0x03, 0xB6, 0x79, 0x7C,
    0x62, 0xDD, 0xDF, 0x3F, 0x71, 0x3A, 0x9D, 0x8B, 0xC4, 0xF6, 0xE7, 0x1D,
    0x52, 0xA8, 0xA9, 0x43, 0x1D, 0x33, 0x51, 0x88, 0x39, 0xBD, 0x73, 0xE9,
    0x5F, 0xBE, 0x82, 0x49, 0x27, 0xE6, 0xB5, 0x53, 0xC1, 0x38, 0xAC, 0x2F,
    0x6D, 0x97, 0x6C, 0xEB, 0x67, 0xC1, 0x5F, 0x67, 0xF8, 0x35, 0x05, 0x5E,
    0xD5, 0x68, 0x80, 0xAA, 0x96, 0xCA, 0x0B, 0x8A, 0xE6, 0xF1, 0xB1, 0x41,
    0xC6, 0x75, 0x94, 0x0A, 0x0A, 0x2A, 0xFA, 0x29,
};

static const unsigned char str1[] = "12345678901234567890";

static const char rnd_seed[] =
    "string to make the random number generator think it has entropy";

static BIO *bio_err = NULL;

int main(int argc, char **argv)
{
    BN_GENCB *cb;
    DSA *dsa = NULL;
    int counter, ret = 0, i, j;
    unsigned char buf[256];
    unsigned long h;
    unsigned char sig[256];
    unsigned int siglen;
    const BIGNUM *p = NULL, *q = NULL, *g = NULL;

    if (bio_err == NULL)
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    CRYPTO_set_mem_debug(1);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    RAND_seed(rnd_seed, sizeof(rnd_seed));

    BIO_printf(bio_err, "test generation of DSA parameters\n");

    cb = BN_GENCB_new();
    if (!cb)
        goto end;

    BN_GENCB_set(cb, dsa_cb, bio_err);
    if (((dsa = DSA_new()) == NULL) || !DSA_generate_parameters_ex(dsa, 1024,
                                                                   seed, 20,
                                                                   &counter,
                                                                   &h, cb))
        goto end;

    BIO_printf(bio_err, "seed\n");
    for (i = 0; i < 20; i += 4) {
        BIO_printf(bio_err, "%02X%02X%02X%02X ",
                   seed[i], seed[i + 1], seed[i + 2], seed[i + 3]);
    }
    BIO_printf(bio_err, "\ncounter=%d h=%ld\n", counter, h);

    DSA_print(bio_err, dsa, 0);
    if (counter != 239) {
        BIO_printf(bio_err, "counter should be 105\n");
        goto end;
    }
    if (h != 2) {
        BIO_printf(bio_err, "h should be 2\n");
        goto end;
    }

    DSA_get0_pqg(dsa, &p, &q, &g);
    i = BN_bn2bin(q, buf);
    j = sizeof(out_q);
    if ((i != j) || (memcmp(buf, out_q, i) != 0)) {
        BIO_printf(bio_err, "q value is wrong\n");
        goto end;
    }

    i = BN_bn2bin(p, buf);
    j = sizeof(out_p);
    if ((i != j) || (memcmp(buf, out_p, i) != 0)) {
        BIO_printf(bio_err, "p value is wrong\n");
        goto end;
    }

    i = BN_bn2bin(g, buf);
    j = sizeof(out_g);
    if ((i != j) || (memcmp(buf, out_g, i) != 0)) {
        BIO_printf(bio_err, "g value is wrong\n");
        goto end;
    }

    DSA_generate_key(dsa);
    DSA_sign(0, str1, 20, sig, &siglen, dsa);
    if (DSA_verify(0, str1, 20, sig, siglen, dsa) == 1)
        ret = 1;

 end:
    if (!ret)
        ERR_print_errors(bio_err);
    DSA_free(dsa);
    BN_GENCB_free(cb);

#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (CRYPTO_mem_leaks(bio_err) <= 0)
        ret = 0;
#endif
    BIO_free(bio_err);
    bio_err = NULL;
    EXIT(!ret);
}

static int dsa_cb(int p, int n, BN_GENCB *arg)
{
    char c = '*';
    static int ok = 0, num = 0;

    if (p == 0) {
        c = '.';
        num++;
    };
    if (p == 1)
        c = '+';
    if (p == 2) {
        c = '*';
        ok++;
    }
    if (p == 3)
        c = '\n';
    BIO_write(BN_GENCB_get_arg(arg), &c, 1);
    (void)BIO_flush(BN_GENCB_get_arg(arg));

    if (!ok && (p == 0) && (num > 1)) {
        BIO_printf(BN_GENCB_get_arg(arg), "error in dsatest\n");
        return 0;
    }
    return 1;
}
#endif
