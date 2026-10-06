# Support notes: deferred items

## Linked-in C port drivers (`erl_driver` ABI)

Status: **deferred** (decision 2026-09-29). We may return to it once the core runtime is complete.

### What it is

`erl_driver.h` is the legacy C API for linked-in port drivers: loading shared objects through `erl_ddll`, the driver
callbacks (`start`, `stop`, `output`, `outputv`, `control`, `call`, `ready_input`, `ready_output`, `timeout`, ...) and
about 130 `driver_*` / `erl_drv_*` functions (`driver_output_term`, `driver_select`, async jobs, threads, mutexes,
driver monitors and timers, port data locks).

Arinsal already implements the drivers built into erts (`inet`, `spawn`, `fd`, `tty`) natively in Rust, so they do not
need this ABI.

### Who needs it in OTP 29

- OTP libraries: practically none (crypto, asn1 and zlib are NIFs; odbc and os_mon use external port programs).
- The erts test suites: `driver_SUITE`, `ddll_SUITE`, `async_ports_SUITE`, `busy_port_SUITE`, and `fp_drv` in
  `float_SUITE` fail until it exists.
- Legacy third-party libraries that still ship linked-in drivers.

### Options considered

| Option | Pros | Cons |
|---|---|---|
| A. Full port, `unsafe` confined to an ABI shim crate (same scheme as the NIF API) | 1:1 with erts; driver suites pass; legacy drivers work; proven pattern | Large surface (~130 functions, async pool, port data locks, `driver_select` on the shared poller, `driver_output_term` format); new `unsafe` inside the shim; roughly 3–4 agent tasks |
| B. Do not port; document as a deliberate deviation | No work | Breaks 1:1; ~5 erts suites stay red forever; legacy drivers cannot load |
| C. Partial port for the test suites only | Smaller at first | In practice the same surface as A, with holes |

### Recommendation

Option A, scheduled after the core work (BeamAsm as default, distribution, trapping BIFs and dirty schedulers,
allocators), in three stages:

1. **D1** — `erl_ddll` loading of `.so` drivers, the basic callbacks, `output` / `control` / `call`, and
   `driver_select` integrated with the shared I/O poller.
2. **D2** — `driver_output_term` / `driver_send_term`, `outputv` / `ErlIOVec`, driver monitors and timers.
3. **D3** — the async thread pool, `erl_drv_*` threads, mutexes and port data locks, busy port states.

`unsafe` only inside a dedicated `arinsal-driver` crate, every block with `// SAFETY:`, its own census cap — the same
rules as the NIF shim.
