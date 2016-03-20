/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef GUARD_MEMWIPE_H
#define GUARD_MEMWIPE_H 1

#include <stdint.h>
#include <stddef.h>

void memwipe(void *mem, uint8_t byte, size_t sz);

#endif
