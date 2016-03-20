/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "util.h"

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

/** Read from <b>fd</b> to <b>buf</b>, until we get <b>count</b> bytes
 * or reach the end of the file. <b>isSocket</b> must be 1 if fd
 * was returned by socket() or accept(), and 0 if fd was returned by
 * open().  Return the number of bytes read, or -1 on error. Only use
 * if fd is a blocking fd. */
ssize_t
read_all(int fd, char *buf, size_t count)
{
  size_t numread = 0;
  ssize_t result;

  while (numread != count) {
    result = read((int)fd, buf+numread, count-numread);

    if (result<0)
      return -1;
    else if (result == 0)
      break;
    numread += result;
  }
  return (ssize_t)numread;
}

int
tor_mem_is_zero(const char *mem, size_t len)
{
  static const char ZERO[] = {
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
  };
  while (len >= sizeof(ZERO)) {
    /* It's safe to use fast_memcmp here, since the very worst thing an
     * attacker could learn is how many initial bytes of a secret were zero */
    if (fast_memcmp(mem, ZERO, sizeof(ZERO)))
      return 0;
    len -= sizeof(ZERO);
    mem += sizeof(ZERO);
  }
  /* Deal with leftover bytes. */
  if (len)
    return fast_memeq(mem, ZERO, len);

  return 1;
}
