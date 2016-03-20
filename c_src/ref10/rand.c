/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "rand.h"
#include "memwipe.h"
#include "util.h"

#include <openssl/sha.h>
#include <openssl/rand.h>

#include <assert.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

/** Try to get <b>out_len</b> bytes of the strongest entropy we can generate,
 * via system calls, storing it into <b>out</b>. Return 0 on success, -1 on
 * failure.  A maximum request size of 256 bytes is imposed.
 */
static int
crypto_strongest_rand_syscall(uint8_t *out, size_t out_len)
{
#if defined(__linux__) && defined(SYS_getrandom)
  static int getrandom_works = 1; /* Be optimitic about our chances... */

  /* getrandom() isn't as straight foward as getentropy(), and has
   * no glibc wrapper.
   *
   * As far as I can tell from getrandom(2) and the source code, the
   * requests we issue will always succeed (though it will block on the
   * call if /dev/urandom isn't seeded yet), since we are NOT specifying
   * GRND_NONBLOCK and the request is <= 256 bytes.
   *
   * The manpage is unclear on what happens if a signal interrupts the call
   * while the request is blocked due to lack of entropy....
   *
   * We optimistically assume that getrandom() is available and functional
   * because it is the way of the future, and 2 branch mispredicts pale in
   * comparision to the overheads involved with failing to open
   * /dev/srandom followed by opening and reading from /dev/urandom.
   */
  if (getrandom_works) {
    long ret;
    /* A flag of '0' here means to read from '/dev/urandom', and to
     * block if insufficient entropy is available to service the
     * request.
     */
    const unsigned int flags = 0;
    do {
      ret = syscall(SYS_getrandom, out, out_len, flags);
    } while (ret == -1 && ((errno == EINTR) ||(errno == EAGAIN)));

    if (ret == -1) {
      assert(errno != EAGAIN);
      assert(errno != EINTR);

      /* Probably ENOSYS. */
      printf("Can't get entropy from getrandom().");
      getrandom_works = 0; /* Don't bother trying again. */
      return -1;
    }

    assert(ret == (long)out_len);
    return 0;
  }

  return -1; /* getrandom() previously failed unexpectedly. */
#elif defined(HAVE_GETENTROPY)
  /* getentropy() is what Linux's getrandom() wants to be when it grows up.
   * the only gotcha is that requests are limited to 256 bytes.
   */
  return getentropy(out, out_len);
#else
  (void) out;
#endif

  /* This platform doesn't have a supported syscall based random. */
  return -1;
}

/** Try to get <b>out_len</b> bytes of the strongest entropy we can generate,
 * via the per-platform fallback mechanism, storing it into <b>out</b>.
 * Return 0 on success, -1 on failure.  A maximum request size of 256 bytes
 * is imposed.
 */
static int
crypto_strongest_rand_fallback(uint8_t *out, size_t out_len)
{
#ifdef _WIN32
  /* Windows exclusively uses crypto_strongest_rand_syscall(). */
  (void)out;
  (void)out_len;
  return -1;
#else
  static const char *filenames[] = {
    "/dev/srandom", "/dev/urandom", "/dev/random", NULL
  };
  int fd, i;
  size_t n;

  for (i = 0; filenames[i]; ++i) {
    fd = open(filenames[i], O_RDONLY, 0);
    if (fd<0) continue;
    n = read_all(fd, (char*)out, out_len);
    close(fd);
    if (n != out_len) {
      return -1;
    }

    return 0;
  }

  return -1;
#endif
}

/** Try to get <b>out_len</b> bytes of the strongest entropy we can generate,
 * storing it into <b>out</b>. Return 0 on success, -1 on failure.  A maximum
 * request size of 256 bytes is imposed.
 */
static int
crypto_strongest_rand_raw(uint8_t *out, size_t out_len)
{
  static const size_t sanity_min_size = 16;
  static const int max_attempts = 3;

  /* For buffers >= 16 bytes (128 bits), we sanity check the output by
   * zero filling the buffer and ensuring that it actually was at least
   * partially modified.
   *
   * Checking that any individual byte is non-zero seems like it would
   * fail too often (p = out_len * 1/256) for comfort, but this is an
   * "adjust according to taste" sort of check.
   */
  memwipe(out, 0, out_len);
  for (int i = 0; i < max_attempts; i++) {
    /* Try to use the syscall/OS favored mechanism to get strong entropy. */
    if (crypto_strongest_rand_syscall(out, out_len) != 0) {
      /* Try to use the less-favored mechanism to get strong entropy. */
      if (crypto_strongest_rand_fallback(out, out_len) != 0) {
        /* Welp, we tried.  Hopefully the calling code terminates the process
         * since we're basically boned without good entropy.
         */
        return -1;
      }
    }

    if ((out_len < sanity_min_size) || !tor_mem_is_zero((char*)out, out_len))
      return 0;
  }

  /* We tried max_attempts times to fill a buffer >= 128 bits long,
   * and each time it returned all '0's.  Either the system entropy
   * source is busted, or the user should go out and buy a ticket to
   * every lottery on the planet.
   */
  return -1;
}

/** Try to get <b>out_len</b> bytes of the strongest entropy we can generate,
 * storing it into <b>out</b>.
 */
void
crypto_strongest_rand(uint8_t *out, size_t out_len)
{
#define DLEN SHA512_DIGEST_LENGTH
  /* We're going to hash DLEN bytes from the system RNG together with some
   * bytes from the openssl PRNG, in order to yield DLEN bytes.
   */
  uint8_t inp[DLEN*2];
  uint8_t tmp[DLEN];
  assert(out);
  while (out_len) {
    crypto_rand((char*) inp, DLEN);
    if (crypto_strongest_rand_raw(inp+DLEN, DLEN) < 0) {
      assert(0);
    }
    if (out_len >= DLEN) {
      SHA512(inp, sizeof(inp), out);
      out += DLEN;
      out_len -= DLEN;
    } else {
      SHA512(inp, sizeof(inp), tmp);
      memcpy(out, tmp, out_len);
      break;
    }
  }
  memwipe(tmp, 0, sizeof(tmp));
  memwipe(inp, 0, sizeof(inp));
#undef DLEN
}

void
crypto_rand(char *to, size_t n)
{
  int r;
  if (n == 0)
    return;

  assert(to);

  r = RAND_bytes((unsigned char*)to, (int)n);
  /* We consider a PRNG failure non-survivable. Let's assert so that we get a
   * stack trace about where it happened.
   */
  assert(r >= 0);
}
