// Copyright (c) 2016 The Talla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "ed25519_ref10.h"

#include "ref10/api.h"

static ERL_NIF_TERM enif_ed25519_ref10_keypair(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
    ErlNifBinary public;
    ErlNifBinary secret;

    if (argc != 0) {
        return enif_make_badarg(env);
    }

    if (!enif_alloc_binary(CRYPTO_PUBLICKEYBYTES, &secret)) {
        return make_error_tuple(env, "alloc_failed");
    }

    if (!enif_alloc_binary(CRYPTO_SECRETKEYBYTES, &public)) {
        return make_error_tuple(env, "alloc_failed");
    }

    ed25519_ref10_keypair(public.data, secret.data);

    return enif_make_tuple2(env, enif_make_binary(env, &public), enif_make_binary(env, &secret));
}

static ERL_NIF_TERM enif_ed25519_ref10_sign(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
    ErlNifBinary signature;

    ErlNifBinary message;
    ErlNifBinary secret;

    unsigned char public[CRYPTO_PUBLICKEYBYTES];

    if ((argc != 2)
            || (!enif_inspect_binary(env, argv[0], &message))
            || (!enif_inspect_binary(env, argv[1], &secret))
            || (secret.size != CRYPTO_SECRETKEYBYTES)) {
        return enif_make_badarg(env);
    }

    if (!ed25519_ref10_public_key(public, secret.data) != 0) {
        return make_error_tuple(env, "ed25519_ref10_public_key_failed");
    }

    if (!enif_alloc_binary(CRYPTO_BYTES, &signature)) {
        return make_error_tuple(env, "alloc_failed");
    }

    if (ed25519_ref10_sign(signature.data, message.data, message.size, secret.data, public) != 0) {
        return make_error_tuple(env, "ed25519_ref10_sign_failed");
    }

    return enif_make_binary(env, &signature);
}

static ERL_NIF_TERM enif_ed25519_ref10_open(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
    ErlNifBinary signature;
    ErlNifBinary message;
    ErlNifBinary public;

    int ret = -1;

    if ((argc != 3)
            || (!enif_inspect_binary(env, argv[0], &signature))
            || (signature.size != CRYPTO_BYTES)
            || (!enif_inspect_binary(env, argv[1], &message))
            || (!enif_inspect_binary(env, argv[2], &public))
            || (public.size != CRYPTO_PUBLICKEYBYTES)) {
        return enif_make_badarg(env);
    }

    ret = ed25519_ref10_open(signature.data, message.data, message.size, public.data);

    return ret == 0 ? enif_make_atom(env, "true") : enif_make_atom(env, "false");
}

static ERL_NIF_TERM enif_ed25519_ref10_secret_key(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
    ErlNifBinary secret;

    if (argc != 0) {
        return enif_make_badarg(env);
    }

    if (!enif_alloc_binary(CRYPTO_SECRETKEYBYTES, &secret)) {
        return make_error_tuple(env, "alloc_failed");
    }

    if (ed25519_ref10_secret_key(secret.data) != 0) {
        return make_error_tuple(env, "ed25519_ref10_secret_key_failed");
    }

    return enif_make_binary(env, &secret);
}

static ERL_NIF_TERM enif_ed25519_ref10_secret_key_expand(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
    ErlNifBinary secret;
    ErlNifBinary seed;

    if ((argc != 1)
            || (!enif_inspect_binary(env, argv[0], &seed))
            || (seed.size != CRYPTO_SEEDBYTES)) {
        return enif_make_badarg(env);
    }

    if (!enif_alloc_binary(CRYPTO_SECRETKEYBYTES, &secret)) {
        return make_error_tuple(env, "alloc_failed");
    }

    if (ed25519_ref10_secret_key_expand(secret.data, seed.data) != 0) {
        return make_error_tuple(env, "ed25519_ref10_secret_key_expand_failed");
    }

    return enif_make_binary(env, &secret);
}

static ERL_NIF_TERM enif_ed25519_ref10_public_key(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
    ErlNifBinary secret;
    ErlNifBinary public;

    if ((argc != 1)
            || (!enif_inspect_binary(env, argv[0], &secret))
            || (secret.size != CRYPTO_SECRETKEYBYTES)) {
        return enif_make_badarg(env);
    }

    if (!enif_alloc_binary(CRYPTO_PUBLICKEYBYTES, &public)) {
        return make_error_tuple(env, "alloc_failed");
    }

    if (ed25519_ref10_public_key(public.data, secret.data) != 0) {
        return make_error_tuple(env, "ed25519_ref10_public_key_failed");
    }

    return enif_make_binary(env, &public);
}

static ErlNifFunc nif_functions[] = {
    {"keypair",           0, enif_ed25519_ref10_keypair, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sign",              2, enif_ed25519_ref10_sign,    ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"open",              3, enif_ed25519_ref10_open,    ERL_NIF_DIRTY_JOB_CPU_BOUND},

    {"secret_key",        0, enif_ed25519_ref10_secret_key},
    {"secret_key_expand", 1, enif_ed25519_ref10_secret_key_expand},

    {"public_key",        1, enif_ed25519_ref10_public_key},
};

static int on_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    return 0;
}

static int on_upgrade(ErlNifEnv *env, void **priv_data, void **old_priv_data, ERL_NIF_TERM load_info)
{
    return 0;
}

ERL_NIF_TERM make_error_tuple(ErlNifEnv *env, char *error)
{
    return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_atom(env, error));
}

ERL_NIF_INIT(ed25519_ref10_nif, nif_functions, on_load, /* reload */ NULL, on_upgrade, /* unload */ NULL);
