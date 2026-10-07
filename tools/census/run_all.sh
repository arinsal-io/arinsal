#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT="$ROOT/docs/census"
TMP="$ROOT/tmp/census"
EBIN="$TMP/ebin"
BOOT="$TMP/census_boot"
mkdir -p "$OUT" "$EBIN"
export ERL_CRASH_DUMP="$TMP/erl_crash.dump"

"$ROOT/tools/census/static.escript"
erlc -W0 -o "$EBIN" "$ROOT/tools/census/census_hook.erl"
erlc -W0 +export_all -o "$EBIN" "$ROOT/bench/bench.erl"
"$ROOT/tools/census/boot.escript" "$(erl -noshell -eval 'io:format("~s",[filename:join([code:root_dir(),"releases","29","start.script"])]),halt().')" "$BOOT"

export CENSUS_ROOT="$ROOT"
export ERL_AFLAGS="-pa $EBIN"

echo 'scenario: bench'
export CENSUS_SCENARIO=bench
erl -noshell -s census_hook start -eval 'census_hook:mark(), bench:fib(25), bench:trees(10), bench:nbody(1000), catch bench:tasks(1000), census_hook:stop(), halt().' > "$TMP/bench.log" 2>&1

echo 'scenario: boot'
export CENSUS_SCENARIO=boot
erl -noshell -boot "$BOOT" -eval 'census_hook:stop(), halt().' > "$TMP/boot.log" 2>&1

echo 'scenario: hello'
export CENSUS_SCENARIO=hello
erl -noshell -boot "$BOOT" -eval 'io:format("hi~n"), census_hook:stop(), halt().' > "$TMP/hello.log" 2>&1

export ELIXIR_ERL_OPTIONS="-boot $BOOT -pa $EBIN"
echo 'scenario: elixir'
export CENSUS_SCENARIO=elixir
elixir -e 'IO.puts(:hi); :census_hook.stop()' > "$TMP/elixir.log" 2>&1

echo 'scenario: iex'
export CENSUS_SCENARIO=iex
iex -e 'IO.puts(:hi); :census_hook.stop(); System.halt()' > "$TMP/iex.log" 2>&1

echo 'scenario: mix'
DEMO="$TMP/census_demo"
rm -rf -- "$DEMO"
env -u CENSUS_SCENARIO mix new "$DEMO" > "$TMP/mix_new.log" 2>&1
if ! rg -q 'census_hook.stop' "$DEMO/test/test_helper.exs"; then
    printf '\nExUnit.after_suite(fn _ -> :census_hook.stop() end)\n' >> "$DEMO/test/test_helper.exs"
fi
export CENSUS_SCENARIO=mix
(cd "$DEMO" && mix test) > "$TMP/mix_test.log" 2>&1

"$ROOT/tools/census/report.escript"
"$ROOT/tools/census/verify.escript"
echo 'census complete'
