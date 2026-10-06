#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

otp_root=${ARINSAL_OTP_ROOT:-$(erl -noshell -eval 'io:format("~s",[code:root_dir()]),halt().')}/lib
elixir_root=${ARINSAL_ELIXIR_ROOT:-$(elixir -e 'IO.write(Path.dirname(Path.dirname(:code.lib_dir(:elixir))))')}/lib
timeout 1800 cargo run -p arinsal-beamjit --example coverage -- "$otp_root"/*/ebin "$elixir_root"/*/ebin
timeout 1800 cargo test -p arinsal-beamjit
