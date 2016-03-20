#define CRYPTO_SECRETKEYBYTES 64
#define CRYPTO_PUBLICKEYBYTES 32
#define CRYPTO_SEEDBYTES 32
#define CRYPTO_BYTES 64
#define CRYPTO_DETERMINISTIC 1

int ed25519_ref10_keypair(unsigned char *pk,unsigned char *sk);
int ed25519_ref10_public_key(unsigned char *pk,const unsigned char *sk);
int ed25519_ref10_secret_key(unsigned char *sk);
int ed25519_ref10_secret_key_expand(unsigned char *sk, const unsigned char *skseed);
int ed25519_ref10_open(const unsigned char *signature, const unsigned char *m, size_t mlen, const unsigned char *pk);
int ed25519_ref10_sign(unsigned char *sig, const unsigned char *m, size_t mlen, const unsigned char *sk,const unsigned char *pk);
