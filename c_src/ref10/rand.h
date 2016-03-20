/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef GUARD_RAND_H
#define GUARD_RAND_H 1

#include <stdint.h>
#include <stddef.h>

void crypto_strongest_rand(uint8_t *out, size_t out_len);
void crypto_rand(char *to, size_t n);

#endif
