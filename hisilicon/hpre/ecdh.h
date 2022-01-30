#ifndef _CRYPTO_ECDH_
#define _CRYPTO_ECDH_

#define ECC_CURVE_NIST_P192 0x0001
#define ECC_CURVE_NIST_P256 0x0002
#define ECC_CURVE_NIST_P384 0x0003
#define ECC_CURVE_NIST_P224 0x0004
#define ECC_CURVE_NIST_P521 0x0006

struct ecdh {
    char *key;
    unsigned short key_size;
};

unsigned int crypto_ecdh_key_len(const struct ecdh *params);

int crypto_ecdh_encode_key(char *buf, unsigned int len, const struct ecdh *p);

int crypto_ecdh_decode_key(const char *buf, unsigned int len, struct ecdh *p);

#endif