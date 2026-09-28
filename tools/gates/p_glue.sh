#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

otp_root=$HOME/.asdf/installs/erlang/29.1.1/lib
elixir_root=$HOME/.asdf/installs/elixir/1.20.4-otp-29/lib
timeout 1800 cargo run -p arinsal-beamjit --example coverage -- "$otp_root"/*/ebin "$elixir_root"/*/ebin
timeout 1800 cargo test -p arinsal-beamjit
