/* Added to ref10 for Tor. We place this in the public domain.  Alternatively,
 * you may have it under the Creative Commons 0 "CC0" license. */
#include "fe.h"
#include "ed25519_ref10.h"
#include "api.h"
#include "memwipe.h"
#include "util.h"
#include "di_ops.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include <openssl/sha.h>

int ed25519_ref10_public_key_from_x225519_public_key(unsigned char *out, const unsigned char *inp, int signbit)
{
  fe u;
  fe one;
  fe y;
  fe uplus1;
  fe uminus1;
  fe inv_uplus1;

  /* From prop228:

   Given a curve25519 x-coordinate (u), we can get the y coordinate
   of the ed25519 key using

         y = (u-1)/(u+1)
  */
  fe_frombytes(u, inp);
  fe_1(one);
  fe_sub(uminus1, u, one);
  fe_add(uplus1, u, one);
  fe_invert(inv_uplus1, uplus1);
  fe_mul(y, uminus1, inv_uplus1);

  fe_tobytes(out, y);

  /* propagate sign. */
  out[31] |= (!!signbit) << 7;

  return 0;
}

int ed25519_ref10_keypair_from_x25519_keypair(unsigned char *public_out, unsigned char *secret_out, int *signbit, unsigned char *x25519_public, unsigned char *x25519_secret) {
    const char string[] = "Derive high part of ed25519 key from curve25519 key";
    unsigned char pubkey_check[CRYPTO_PUBLICKEYBYTES];
    SHA512_CTX ctx;
    uint8_t sha512_output[64];

    memcpy(secret_out, x25519_secret, 32);
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, secret_out, 32);
    SHA512_Update(&ctx, string, sizeof(string));
    SHA512_Final(sha512_output, &ctx);
    memcpy(secret_out + 32, sha512_output, 32);

    ed25519_ref10_public_key(public_out, secret_out);

    *signbit = public_out[31] >> 7;

    ed25519_ref10_public_key_from_x225519_public_key(pubkey_check, x25519_public, *signbit);

    assert(fast_memeq(pubkey_check, public_out, 32));

    memwipe(&pubkey_check, 0, sizeof(pubkey_check));

    memwipe(&ctx, 0, sizeof(ctx));
    memwipe(sha512_output, 0, sizeof(sha512_output));

    return 0;
}
