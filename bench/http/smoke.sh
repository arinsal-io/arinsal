#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
PIDS=()
cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

cd "$ROOT"
mkdir -p bench/out
(cd examples/http/go && go build -o "$TMP/go" .)
(cd examples/http/rust && cargo build --release)
(cd examples/http/elixir_bandit && MIX_ENV=prod mix deps.get >/dev/null && MIX_ENV=prod mix compile)

start() {
  local name="$1" port="$2"; shift 2
  PORT="$port" "$@" >"$TMP/$name.log" 2>&1 &
  PIDS+=("$!")
  for _ in $(seq 1 100); do
    if curl -fsS "http://127.0.0.1:$port/plaintext" >/dev/null 2>&1; then return; fi
    sleep 0.1
  done
  cat "$TMP/$name.log"
  echo "$name failed to start" >&2
  exit 1
}

start go 8081 "$TMP/go"
start rust 8082 "$ROOT/examples/http/rust/target/release/arinsal-http-rust"
start elixir 8083 env MIX_ENV=prod ELIXIR_ERL_OPTIONS='+S 4:4' bash -c 'cd "$1" && exec mix run --no-halt' _ "$ROOT/examples/http/elixir_bandit"

for endpoint in plaintext json work echo; do
  for spec in "go:8081" "rust:8082" "elixir:8083"; do
    name="${spec%%:*}"; port="${spec##*:}"
    case "$endpoint" in
      plaintext) url="http://127.0.0.1:$port/plaintext"; expected_type='text/plain';;
      json) url="http://127.0.0.1:$port/json"; expected_type='application/json';;
      work) url="http://127.0.0.1:$port/work?n=20"; expected_type='application/json';;
      echo) url="http://127.0.0.1:$port/echo"; expected_type='application/json';;
    esac
    if [ "$endpoint" = echo ]; then
      curl -fsS -w '%{content_type}' -o "$TMP/$name-$endpoint" -H 'Content-Type: application/json' -d '{"message":"Hello, World!"}' "$url" >"$TMP/$name-$endpoint.type"
    else
      curl -fsS -w '%{content_type}' -o "$TMP/$name-$endpoint" "$url" >"$TMP/$name-$endpoint.type"
    fi
    test "$(cat "$TMP/$name-$endpoint.type")" = "$expected_type"
  done
  cmp "$TMP/go-$endpoint" "$TMP/rust-$endpoint"
  cmp "$TMP/go-$endpoint" "$TMP/elixir-$endpoint"
  printf 'PASS %s: byte-identical across Go, Rust, Elixir\n' "$endpoint"
done

test "$(cat "$TMP/go-plaintext")" = 'Hello, World!'
test "$(cat "$TMP/go-json")" = '{"message":"Hello, World!"}'
python3 - "$TMP/go-work" <<'PY'
import json, sys
value = json.load(open(sys.argv[1]))
assert value["n"] == 20 and value["fib"] == 6765 and len(value["items"]) == 20
assert value["items"][1] == {"id": 1, "name": "item-1", "score": 1.5}
PY
for spec in "go:8081" "rust:8082" "elixir:8083"; do
  name="${spec%%:*}"; port="${spec##*:}"
  curl -fsS "http://127.0.0.1:$port/work?n=1001" >"$TMP/$name-work-cap"
done
cmp "$TMP/go-work-cap" "$TMP/rust-work-cap"
cmp "$TMP/go-work-cap" "$TMP/elixir-work-cap"
python3 - "$TMP/go-work-cap" <<'PY'
import json, sys
value = json.load(open(sys.argv[1]))
a, b = 0, 1
for _ in range(1000):
    a, b = b, a + b
assert value["n"] == 1000 and value["fib"] == a and len(value["items"]) == 1000
PY
echo 'All HTTP smoke checks passed.'
