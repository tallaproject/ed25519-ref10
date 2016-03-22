%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @private
%%% ----------------------------------------------------------------------------
-module(ed25519_ref10_nif).

%% Private API.
-export([keypair/0,
         sign/2,
         open/3,
         secret_key/0,
         secret_key_expand/1,
         public_key/1,
         keypair_from_x25519_keypair/2,
         public_key_from_x25519_public_key/2
        ]).

%% Initializer.
-on_load(init/0).

%% NIF.
-define(nif_stub, nif_stub_error(?LINE)).

-spec init() -> ok | {error, any()}.
init() ->
    Module = "ed25519_ref10",
    File = case code:priv_dir(?MODULE) of
        {error, bad_name} ->
            case code:which(?MODULE) of
                DirectoryName when is_list(DirectoryName) ->
                    filename:join([filename:dirname(DirectoryName), "..", "priv", Module]);

                _Otherwise ->
                    filename:join(["..", "priv", Module])
            end;

        DirectoryName when is_list(DirectoryName) ->
            filename:join([DirectoryName, Module])
    end,
    erlang:load_nif(File, 0).

%% @private
-spec keypair() -> {binary(), binary()}.
keypair() ->
    ?nif_stub.

%% @private
-spec sign(binary(), binary()) -> binary().
sign(_, _) ->
    ?nif_stub.

%% @private
-spec open(binary(), binary(), binary()) -> boolean().
open(_, _, _) ->
    ?nif_stub.

%% @private
-spec secret_key() -> binary().
secret_key() ->
    ?nif_stub.

%% @private
-spec secret_key_expand(binary()) -> binary().
secret_key_expand(_) ->
    ?nif_stub.

%% @private
-spec public_key(binary()) -> binary().
public_key(_) ->
    ?nif_stub.

%% @private
-spec keypair_from_x25519_keypair(binary(), binary()) -> {binary(), binary()}.
keypair_from_x25519_keypair(_, _) ->
    ?nif_stub.

%% @private
-spec public_key_from_x25519_public_key(binary(), non_neg_integer()) -> binary().
public_key_from_x25519_public_key(_, _) ->
    ?nif_stub.

%% @private
-spec nif_stub_error(Line :: non_neg_integer()) -> no_return().
nif_stub_error(Line) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, Line}).
