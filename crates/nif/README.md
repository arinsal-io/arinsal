# Arinsal NIF host

`load_nif(path, LoadInfo { module, term })` opens an OTP 29 NIF library, checks its entry, runs its load callback, and returns a `NifLibrary`. Use `lookup(name, arity)` and `NifFunction::call` with a BIF `Ctx`; use `call_with_pid` when the calling process ID is available. `functions()` exposes the name, arity, function pointer, and dirty flags to a future module loader. `upgrade_nif` invokes the replacement library's upgrade callback.

The final executable must link `arinsal-nif`, call `ensure_exports()`, and export its symbols (`-Wl,-export_dynamic` on macOS, `-rdynamic` on Linux). `arinsal-cli` does this. The crate's integration test executables also export symbols and serve as standalone NIF hosts.

`ErlNifEnv::bound` uses the caller's heap; `enif_alloc_env` owns an independent heap. Resource terms and resource-backed binaries retain their native owner through copying and garbage collection. `VmHooks` supplies delivery, name lookup, process monitoring, and reactor registration when the VM connects those services. Without VM hooks, `enif_send` records copies in `take_test_messages()`, monitor registration reports no live monitor, and selection reports `ERL_NIF_SELECT_NOTSUP`.

`enif_schedule_nif` invokes the scheduled callback immediately on the calling thread. Dirty flags are accepted but no dirty scheduler is present. I/O queues currently coalesce segments. Formatting supports common `printf` specifiers and `%T`; the complete erts formatter grammar is not implemented. The differential C test covers the supported paths and uses the same NIF in OTP and Arinsal.
