# NIF host spike (OTP 29.1.1)

Build and run on macOS arm64:

```sh
mkdir -p tmp
inc=$(erl -noshell -eval 'io:format("~s/usr/include",[code:root_dir()]), halt().')
cc -O2 -fPIC -bundle -undefined dynamic_lookup -I"$inc" bench/nif/nb.c -o tmp/nb.so
cargo build -p nif_spike --release
./target/release/nif_spike tmp/nb.so
./target/release/nif_spike "$(find "$(dirname "$inc")/../lib" -path '*/crypto-*/priv/lib/crypto.so' -print -quit)" --load
nm -gU target/release/nif_spike | grep _enif_
bash tools/nif_spike/run_dylib_probe.sh
```

`build.rs` compiles and runs `layout.c` against the installed header, then generates
Rust compile-time size and offset assertions. It parses all 180 actual function
declarations in `erl_nif_api_funcs.h`; the 155 functions not implemented by this
spike abort with their names if called. The task description says 185, but the
OTP 29.1.1 header has 180 declarations. The C shim implements variadic
`enif_snprintf`, `enif_set_option`, pthread mutexes, and dynamic library access.
Toy resource types and terms only support the observed load path. They are not
equivalent to erts resource types and must not be used for real crypto calls.

The observed macOS arm64 layout is:

| Type | Size | Field offsets in header order |
| --- | ---: | --- |
| `ERL_NIF_TERM` | 8 | scalar |
| `ErlNifEntry` | 96 | 0, 4, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88 |
| `ErlNifFunc` | 32 | 0, 8, 16, 24 |
| `ErlNifBinary` | 40 | 0, 8, 16, 24 |
| `ErlNifResourceTypeInit` | 40 | 0, 8, 16, 24, 32 |

`crypto.so` links `/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib` and
`libSystem.B.dylib`. It references 52 `enif_*` symbols, all in the header,
and no `erl_drv_*` or `erts_*` symbols. Its `nif_init` returns 2.18, name
`crypto`, 70 functions. The load callback creates five resource types,
registers an unload-thread option, opens `crypto_callback.so`, resolves
`get_crypto_callbacks`, and returns zero. This establishes loading and
initialization, not crypto function compatibility.

`nm -u crypto.so | awk '{print $NF}' | sort -u` has these symbol groups:

| Prefix | Count |
| --- | ---: |
| `enif_` | 52 |
| `BN_`, `CRYPTO_`, `EC_`, `ENGINE_`, `ERR_`, `EVP_` | 22, 3, 6, 31, 1, 155 |
| `OBJ_`, `OPENSSL_`, `OSSL_`, `PKCS5_`, `RAND_` | 1, 2, 8, 1, 2 |
| Other system/OpenSSL symbols | 12 |
| `erl_drv_`, `erts_` | 0, 0 |

The `enif_` imports are:

```text
alloc alloc_binary alloc_env alloc_resource consume_timeslice dlopen dlsym
free free_env get_atom get_int get_list_cell get_list_length get_long
get_map_value get_resource get_tuple get_uint get_ulong inspect_binary
inspect_iolist_as_binary is_atom is_binary is_empty_list is_list is_map
is_tuple make_atom make_badarg make_binary make_copy make_int make_list
make_list_cell make_list_from_array make_map_from_arrays make_new_binary
make_resource make_string make_tuple mutex_create mutex_destroy mutex_lock
mutex_unlock open_resource_type raise_exception realloc_binary
release_binary release_resource schedule_nif set_option snprintf
```

Each name above has the `enif_` prefix in the actual symbol table.

The Rust binary uses `-Wl,-export_dynamic` on macOS. The OTP executable uses
`DEXPORT`, configured to `-Wl,-export-dynamic` when accepted. On Linux this
spike uses `-rdynamic`; the NIF itself should be built with `-shared -fPIC`.
Docker was unavailable during the spike, so Linux execution is unverified.

The separate dylib probe loads a dylib exporting all 180 names with
`RTLD_GLOBAL`. `nb.so` opens and returns its entry; the installed `crypto.so`
fails to open because dyld expects `_enif_alloc` in the main executable.
`nm -m crypto.so` labels the reference `(from executable)`. For an embedded VM,
the executable must export the symbols, or a separate shim must be tested
with an explicit rebinding or relinking strategy. A plain host dylib loaded
with `RTLD_GLOBAL` is insufficient for this installed bundle.

The direct `add/2` callback benchmark excludes BEAM dispatch and scheduling.
It is a lower-bound ABI call measurement, not directly comparable to the
OTP 25 BEAM numbers (17 ns empty NIF, 24.6 ns add) in `docs/plan.md`.
