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

%% @private
-spec keypair() -> term().
keypair() ->
    #{ secret := SecretKey, public := PublicKey } = ed25519_ref10:keypair(),
    {SecretKey, PublicKey}.
