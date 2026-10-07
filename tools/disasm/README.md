# BEAM operand cross-check

`cargo run -p arinsal-cli -- disasm --check-all` checks the installed OTP 29.1.1
and Elixir 1.20.4 `.beam` files, including OTP's preloaded modules under
`erts-17.1`. Paths can be passed to restrict the corpus. The same check runs
from `cargo test -p arinsal-beam --test disasm_operands`.

`dump.escript <file.beam> <output.etf>` writes the complete
`beam_disasm:file/1` term. Its `--batch <manifest> <output-dir>` mode uses one
Erlang VM and parallel workers. Manifest paths are newline separated; output
files are numbered from one.

The Rust renderer owns instruction grouping, operand resolution, import and
lambda lookup, and opcode-specific rewrites. `check.escript` parses its Erlang
terms and compares them structurally with the reference dump, reporting the
first differing instruction in each module. It decodes literal ETF bytes before
comparison because ETF map entry order can differ between the BEAM literal
table and a fresh `term_to_binary/1` call. A second check compares encoded
typed register and literal indices exactly: it compiles a temporary copy of
OTP's `beam_disasm.erl` that exposes type indices and records literal indices.
The original OTP source is never changed.

`arinsal disasm <file.beam> --format erl` materializes only literals and type
records through `expand.escript`; the instruction rendering remains Rust-owned.
This command requires the reference Erlang installation until `arinsal-etf`'s
decoder and a local type formatter are available.
