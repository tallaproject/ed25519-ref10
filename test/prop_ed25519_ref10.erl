%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% -----------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Property Tests for ed25519_ref10.
%%% @end
%%% -----------------------------------------------------------
-module(prop_ed25519_ref10).

-include_lib("proper/include/proper.hrl").

-spec prop_keypair() -> term().
prop_keypair() ->
    ?FORALL({S, P}, keypair(),
       begin
           64 = byte_size(S),
           32 = byte_size(P),

           P  =:= ed25519_ref10:public_key(S)
       end).

-spec prop_sign_open() -> term().
prop_sign_open() ->
    ?FORALL({{S, P}, M}, {keypair(), binary()},
       begin
           Signature = ed25519_ref10:sign(M, S),
           ed25519_ref10:open(Signature, M, P)
       end).

-spec prop_secret_key_expand() -> term().
prop_secret_key_expand() ->
    ?FORALL(Seed, binary(32),
       begin
           SecretA = ed25519_ref10:secret_key_expand(Seed),
           SecretB = ed25519_ref10:secret_key_expand(Seed),
           SecretA =:= SecretB
       end).

-spec prop_x25519_key_conversion() -> term().
prop_x25519_key_conversion() ->
    ?FORALL(X25519KeyPair, x25519_keypair(),
        begin
            X25519P = maps:get(public, X25519KeyPair),
            {#{ public := Ed25519P }, SignBit} = ed25519_ref10:keypair_from_x25519_keypair(X25519KeyPair),
            Ed25519P =:= ed25519_ref10:public_key_from_x25519_public_key(X25519P, SignBit)
        end).

-spec prop_x25519_key_sign_open() -> term().
prop_x25519_key_sign_open() ->
    ?FORALL({X25519KeyPair, M}, {x25519_keypair(), binary()},
       begin
           {#{ secret := S, public := P }, _SignBit} = ed25519_ref10:keypair_from_x25519_keypair(X25519KeyPair),
           Signature = ed25519_ref10:sign(M, S),
           ed25519_ref10:open(Signature, M, P)
       end).

%% @private
-spec keypair() -> term().
keypair() ->
    #{ secret := SecretKey, public := PublicKey } = ed25519_ref10:keypair(),
    {SecretKey, PublicKey}.

%% @private
-spec x25519_keypair() -> term().
x25519_keypair() ->
    enacl_ext:curve25519_keypair().
