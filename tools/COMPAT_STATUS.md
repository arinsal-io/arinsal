# Compatibility Status

- **Date**: 2026-09-27
- **Git Commit**: `5a1a34c`

## Probe Results

### BIF Probe (`tools/bif_probe/REPORT.md`)

- **Total snippets**: 62
- **Matches**: 62 (100.0%)
- **Mismatches**: 0 (0.0%)

#### Remaining Mismatches
None.

#### Delta vs Previous REPORT.md
- **Fixed**: 0
- **Regressed**: 0
- **Summary**: No changes in status; all 62/62 snippets continue to match reference ERTS.

---

### Elixir Probe (`tools/elixir_probe/REPORT.md`)

- **Total snippets**: 60
- **Matches**: 60 (100.0%)
- **Mismatches**: 0 (0.0%)

#### Remaining Mismatches
None.

#### Delta vs Previous REPORT.md
- **Fixed**: 7 snippets (100% resolution of previous failures)
  1. Snippet 14: `Custom Protocol defprotocol` (maps/structs/protocols)
     - Previous: `exit 1: ** (Protocol.UndefinedError) protocol Describable not implemented for 42 of type Integer`
     - Current: MATCH (`int:42`)
  2. Snippet 19: `Try/rescue top-level eval` (try/rescue/catch/after)
     - Previous: `exit 1: ** (ErlangError) Erlang error: :"<Map:0x...>" ...`
     - Current: MATCH (`test failure`)
  3. Snippet 20: `Try/catch top-level throw` (try/rescue/catch/after)
     - Previous: `exit 1: ** (ErlangError) Erlang error: :secret_value`
     - Current: MATCH (`secret_value`)
  4. Snippet 29: `Top-level self() evaluation` (spawn/send/receive with after)
     - Previous: `exit 1: ** (EXIT from #PID<...>) :error`
     - Current: MATCH (`true`)
  5. Snippet 31: `Top-level :ets.new evaluation` (ETS via :ets)
     - Previous: `exit 1: ** (EXIT from #PID<...>) :error`
     - Current: MATCH (`true`)
  6. Snippet 50: `Port.open execution` (Port / System)
     - Previous: `exit 1: arinsal: unsupported BIF erlang:bump_reductions/1 (called from prim_eval:arg_reg_alloc/0)`
     - Current: MATCH (`test`)
  7. Snippet 51: `Multi-clause guard ordering` (Compiler / Guards)
     - Previous: Reference `{:even, :odd}` vs Arinsal `{:odd, :odd}` (clause ordering reversed)
     - Current: MATCH (`{:even, :odd}`)
- **Regressed**: 0
- **Summary**: Compatibility improved from 53/60 (88.3%) to 60/60 (100.0%).
