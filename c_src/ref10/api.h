#define CRYPTO_SECRETKEYBYTES 64
#define CRYPTO_PUBLICKEYBYTES 32
#define CRYPTO_SEEDBYTES 32
#define CRYPTO_BYTES 64
#define CRYPTO_DETERMINISTIC 1

#include <stddef.h>

int ed25519_ref10_public_key(unsigned char *pk,const unsigned char *sk);
int ed25519_ref10_secret_key_expand(unsigned char *sk, const unsigned char *skseed);
int ed25519_ref10_open(const unsigned char *signature, const unsigned char *m, size_t mlen, const unsigned char *pk);
int ed25519_ref10_sign(unsigned char *sig, const unsigned char *m, size_t mlen, const unsigned char *sk,const unsigned char *pk);

int ed25519_ref10_public_key_from_x225519_public_key(unsigned char *out, const unsigned char *inp, int signbit);
int ed25519_ref10_keypair_from_x25519_keypair(unsigned char *public_out, unsigned char *secret_out, int *signbit, unsigned char *x25519_public, unsigned char *x25519_secret);
