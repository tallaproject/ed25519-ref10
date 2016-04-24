/* Modified for Tor: new API, 64-byte secret keys. */

#include <string.h>
#include "crypto_hash_sha512.h"
#include "ge.h"
#include "memwipe.h"
#include "api.h"

int ed25519_ref10_secret_key_expand(unsigned char *sk, const unsigned char *skseed)
{
  crypto_hash_sha512(sk,skseed,32);
  sk[0] &= 248;
  sk[31] &= 63;
  sk[31] |= 64;

  return 0;
}

int ed25519_ref10_public_key(unsigned char *pk,const unsigned char *sk)
{
  ge_p3 A;

  ge_scalarmult_base(&A,sk);
  ge_p3_tobytes(pk,&A);

  return 0;
}
