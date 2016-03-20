/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef GUARD_UTIL_H
#define GUARD_UTIL_H 1

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <string.h>

#define fast_memcmp(a,b,c) (memcmp((a),(b),(c)))
#define fast_memeq(a,b,c)  (0==memcmp((a),(b),(c)))
#define fast_memneq(a,b,c) (0!=memcmp((a),(b),(c)))

ssize_t read_all(int fd, char *buf, size_t count);

int tor_mem_is_zero(const char *mem, size_t len);

#endif
