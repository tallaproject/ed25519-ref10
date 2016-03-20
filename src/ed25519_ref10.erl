%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Ed25519 Ref10 API
%%% @end
%%% ----------------------------------------------------------------------------
-module(ed25519_ref10).

%% API.
-export([keypair/0,
         sign/2,
         open/3,
         secret_key/0,
         secret_key_expand/1,
         public_key/1
        ]).

%% Types.
-export_type([public_key/0,
              secret_key/0,
              keypair/0,
              signature/0
             ]).

-type public_key() :: binary().
-type secret_key() :: binary().
-type keypair()    :: #{ public => public_key(), secret => secret_key() }.

-type signature()  :: binary().
-type seed()       :: binary().

%% @doc Generate a new Ed25519 keypair.
-spec keypair() -> keypair().
keypair() ->
    {PublicKey, SecretKey} = ed25519_ref10_nif:keypair(),
    #{ secret => SecretKey, public => PublicKey }.

%% @doc Sign a given message using a secret key.
-spec sign(Message, SecretKey) -> Signature
    when
        Message   :: iolist(),
        SecretKey :: secret_key(),
        Signature :: signature().
sign(Message, SecretKey) ->
    ed25519_ref10_nif:sign(Message, SecretKey).

%% @doc Verify a given signature using a public key.
-spec open(Signature, Message, PublicKey) -> boolean()
    when
        Signature :: signature(),
        Message   :: iolist(),
        PublicKey :: public_key().
open(Signature, Message, PublicKey) ->
    ed25519_ref10_nif:open(Signature, Message, PublicKey).

%% @doc Generate a new Ed25519 secret key.
-spec secret_key() -> secret_key().
secret_key() ->
    ed25519_ref10_nif:secret_key().

%% @doc Generate a new Ed25519 secret key from a given seed.
-spec secret_key_expand(Seed) -> secret_key()
    when
        Seed :: seed().
secret_key_expand(Seed) ->
    ed25519_ref10_nif:secret_key_expand(Seed).

%% @doc Generate a new Ed25519 public key from a given secret key.
-spec public_key(SecretKey) -> PublicKey
    when
        SecretKey :: secret_key(),
        PublicKey :: public_key().
public_key(SecretKey) ->
    ed25519_ref10_nif:public_key(SecretKey).
