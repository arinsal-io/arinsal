#!/usr/bin/env bash
# Erlang-to-NIF bridge cost: empty call, add, dirty, binary data, and list.
set -e
cd "$(dirname "$0")"
INC=$(erl -noshell -eval 'io:format("~s/usr/include",[code:root_dir()]), halt().')
if [ "$(uname)" = "Darwin" ]; then
  cc -O2 -fPIC -bundle -undefined dynamic_lookup -I"$INC" nb.c -o nb.so
else
  cc -O2 -fPIC -shared -I"$INC" nb.c -o nb.so
fi
erlc nb.erl
erl -noshell -s nb main
