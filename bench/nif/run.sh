#!/usr/bin/env bash
# Вартість мосту Erlang <-> NIF: порожній виклик, add, dirty, бінарні дані, список.
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
