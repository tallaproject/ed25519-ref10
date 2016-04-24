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
         public_key/1,

         keypair_from_x25519_keypair/1,
         public_key_from_x25519_public_key/2
        ]).

%% Types.
-export_type([public_key/0,
              secret_key/0,
              keypair/0,
              signature/0,

              x25519_public_key/0,
              x25519_secret_key/0,
              x25519_keypair/0
             ]).

-type public_key() :: binary().
-type secret_key() :: binary().
-type keypair()    :: #{ public => public_key(), secret => secret_key() }.

-type signature()  :: binary().
-type seed()       :: binary().

-type x25519_public_key() :: binary().
-type x25519_secret_key() :: binary().
-type x25519_keypair()    :: #{ public => x25519_public_key(), secret => x25519_secret_key() }.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%% @doc Generate a new Ed25519 keypair.
-spec keypair() -> keypair().
keypair() ->
    SecretKey = secret_key(),
    PublicKey = public_key(SecretKey),
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
    Seed = enacl:randombytes(32),
    ed25519_ref10_nif:secret_key_expand(Seed).

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

%% @doc Convert a given X25519 keypair to an Ed25519 keypair.
-spec keypair_from_x25519_keypair(X25519KeyPair) -> {Ed25519KeyPair, SignBit}
    when
        X25519KeyPair  :: x25519_keypair(),
        Ed25519KeyPair :: keypair(),
        SignBit        :: 0 | 1.
keypair_from_x25519_keypair(#{ secret := X25519SecretKey, public := X25519PublicKey }) ->
    {PublicKey, SecretKey, SignBit} = ed25519_ref10_nif:keypair_from_x25519_keypair(X25519PublicKey, X25519SecretKey),
    {#{ secret => SecretKey, public => PublicKey }, SignBit}.

%% @doc Convert a given X25519 public key to an Ed25519 public key.
-spec public_key_from_x25519_public_key(X25519PublicKey, X25519SignBit) -> Ed25519PublicKey
    when
        X25519PublicKey  :: x25519_public_key(),
        X25519SignBit    :: 0 | 1,
        Ed25519PublicKey :: public_key().
public_key_from_x25519_public_key(X25519PublicKey, X25519SignBit) ->
    ed25519_ref10_nif:public_key_from_x25519_public_key(X25519PublicKey, X25519SignBit).

-ifdef(TEST).
decode_base16(Encoded) when is_list(Encoded) ->
    decode_base16(iolist_to_binary(Encoded));

decode_base16(Encoded) when is_binary(Encoded) ->
    case Encoded of
        <<>> ->
            <<>>;

        <<A:8/integer>> ->
            <<(list_to_integer([A], 16))>>;

        <<A:8/integer, B:8/integer, Rest/binary>> ->
            <<(list_to_integer([A, B], 16)), (decode_base16(Rest))/binary>>
    end.

keypair_test() ->
    #{ secret := Secret, public := Public } = keypair(),
    [
        ?assertEqual(byte_size(Secret), 64),
        ?assertEqual(byte_size(Public), 32),
        ?assertEqual(Public, public_key(Secret))
    ].

sign_test() ->
    #{ secret := Secret, public := Public } = keypair(),
    Signature = sign(<<"Hello world!">>, Secret),
    [
        ?assert(open(Signature, <<"Hello world!">>, Public))
    ].

secret_key_expand_test() ->
    Seed    = <<0:256>>,
    SecretA = secret_key_expand(Seed),
    SecretB = secret_key_expand(Seed),
    [
        ?assertEqual(SecretA, SecretB),
        ?assertEqual(public_key(SecretA), public_key(SecretB))
    ].

x25519_public_key_conversion_1_test() ->
    X25519PublicKey = decode_base16("36ECF106998BF6EF5DAC2A630DD2A8FE4F90625090E5D32D2EE5E65375347C25"),
    X25519SecretKey = decode_base16("70CFF2118989237E0D923D2CD404F3E51F785E0687FC63A3A74B21985666E77E"),
    X25519KeyPair   = #{ secret => X25519SecretKey, public => X25519PublicKey },

    SignBit = 1,

    Ed25519PublicKey = decode_base16("851B859F1EC9E2C87F36F943EFBC48BF7BBEEABA6ED3C2510C9AA95530F0678F"),
    Ed25519SecretKey = decode_base16(["70CFF2118989237E0D923D2CD404F3E51F785E0687FC63A3A74B21985666E77E"
                                      "68CC3C08312ADD636FF497B329BF5E37D7419A4FED50A0C9C79CF73357845F58"]),
    Ed25519KeyPair   = #{ secret => Ed25519SecretKey, public => Ed25519PublicKey },
    [
        ?assertEqual(Ed25519PublicKey, public_key_from_x25519_public_key(X25519PublicKey, SignBit)),
        ?assertEqual({Ed25519KeyPair, SignBit}, keypair_from_x25519_keypair(X25519KeyPair))
    ].

x25519_public_key_conversion_2_test() ->
    X25519PublicKey = decode_base16("453A6975E5E2E18FB248C3A5AC8163B41131D346BB95C12B313F3CBFD063E858"),
    X25519SecretKey = decode_base16("3840718865390DA1E93AF12E3293D57BBCC1E4F529C30B9B62F0E1ABEBD02157"),
    X25519KeyPair   = #{ secret => X25519SecretKey, public => X25519PublicKey },

    SignBit = 0,

    Ed25519PublicKey = decode_base16("6BEF0C559B20AAD38F59B7111F46C0E17A12686D36F9F6153D5F32441CD33112"),
    Ed25519SecretKey = decode_base16(["3840718865390DA1E93AF12E3293D57BBCC1E4F529C30B9B62F0E1ABEBD02157",
                                      "2B1CDC671ECB8D3BDABB1109DF9E8F3221EE5882DE6848836BCA67A7C94E9B2D"]),
    Ed25519KeyPair   = #{ secret => Ed25519SecretKey, public => Ed25519PublicKey },
    [
        ?assertEqual(Ed25519PublicKey, public_key_from_x25519_public_key(X25519PublicKey, SignBit)),
        ?assertEqual({Ed25519KeyPair, SignBit}, keypair_from_x25519_keypair(X25519KeyPair))
    ].
-endif.
