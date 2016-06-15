// Copyright (c) 2016 The Talla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#ifndef GUARD_ED25519_REF10_H
#define GUARD_ED25519_REF10_H 1

#include "erl_nif.h"

#define ATOM(Name, Value) { Name = enif_make_atom(env, Value); }

ERL_NIF_TERM make_error_tuple(ErlNifEnv *env, char *error);

#endif
