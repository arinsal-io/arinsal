# Distribution and Tracing Audit

This document catalogues the C-implemented BIFs and native machinery that Erlang/OTP 29.1.1 provides for distribution and tracing, alongside their current status in Arinsal.

## 1. Distribution

### BIFs

| MFA | C Implementation | Purpose | Arinsal Status |
| --- | --- | --- | --- |
| `erlang:monitor_node/2` | `dist.c:6665` | Monitors a node for connections or disconnections. | Missing |
| `erlang:monitor_node/3` | `dist.c:6657` | Monitors a node with specific options. | Missing |
| `erlang:node/0` | `dist.c:6230` | Returns the name of the local node. | `crates/vm/src/natives/node.rs:50` |
| `erlang:node/1` | `dist.c:6219` | Returns the node name of a given pid, port, or ref. | `crates/vm/src/natives/node.rs:59` |
| `erlang:nodes/0` | `dist.c:6240` | Returns a list of all visible nodes connected to this node. | `crates/vm/src/natives/node.rs:68` |
| `erlang:nodes/1` | `dist.c:6245` | Returns a list of nodes matching a specified type or state. | `crates/vm/src/natives/node.rs:77` |
| `erlang:nodes/2` | `dist.c:6250` | Returns nodes matching criteria, accepting an options map. | `crates/vm/src/natives/node.rs:86` |
| `erlang:setnode/2` | `dist.c:4978` | Initializes distribution, setting the node name and creation ID. | Missing |
| `erlang:dist_get_stat/1` | `dist.c:4489` | Retrieves statistics for a given distribution controller. | Missing |
| `erlang:dist_ctrl_input_handler/2` | `dist.c:4533` | Registers a process as an input handler for a distribution controller. | Missing |
| `erlang:dist_ctrl_put_data/2` | `dist.c:4333` | Puts data into the output queue of a distribution channel. | Missing |
| `erlang:dist_ctrl_get_data/1` | `dist.c:4559` | Retrieves queued output data from a distribution controller. | Missing |
| `erlang:dist_ctrl_get_data_notification/1` | `dist.c:4273` | Requests a notification when data becomes available in a controller. | Missing |
| `erlang:dist_ctrl_get_opt/2` | `dist.c:4452` | Reads a specific option from a distribution channel. | Missing |
| `erlang:dist_ctrl_set_opt/3` | `dist.c:4409` | Sets an option on a distribution channel. | Missing |
| `erts_internal:create_dist_channel/3` | `dist.c:5127` | Creates a new internal distribution channel structure. | Missing |
| `erts_internal:spawn_request/4` | `bif.c:1078` | Submits an asynchronous spawn request (local or remote). | Missing |
| `erts_internal:dist_spawn_request/4` | `dist.c:5827` | Submits a spawn request directed specifically at a remote node. | Missing |
| `erlang:spawn_request_abandon/1` | `bif.c:1166` | Cancels a previously submitted asynchronous spawn request. | Missing |
| `erlang:alias/1` | `bif.c:5852` | Creates a process alias for receiving messages (often used remotely). | `crates/vm/src/natives/proc.rs:1194` |
| `erlang:unalias/1` | `bif.c:5896` | Deactivates a process alias. | `crates/vm/src/natives/proc.rs:1195` |
| `erts_debug:dist_ext_to_term/2` | `external.c:1340` | Converts an external term format sequence from distribution back to a term. | Missing |

### Non-BIF C Machinery (dist.c, erl_node_tables.c)

| Function / Component | C Implementation | Purpose | Arinsal Status |
| --- | --- | --- | --- |
| `erts_dsig_send_link` | `dist.c:1454` | Encodes and sends a distribution signal for process linking. | Missing |
| `erts_dsig_send_unlink` | `dist.c:1461` | Encodes and sends a distribution signal for unlinking. | Missing |
| `erts_dsig_send_m_exit` | `dist.c:1499` | Encodes and sends a monitor exit signal remotely. | Missing |
| `erts_dsig_send_monitor` | `dist.c:1528` | Encodes and sends a monitor setup signal remotely. | Missing |
| `erts_dsig_send_demonitor` | `dist.c:1554` | Encodes and sends a monitor teardown signal remotely. | Missing |
| `erts_dsig_send_msg` | `dist.c:1592` | Encodes and sends a standard inter-process message across nodes. | Missing |
| `erts_dsig_send_exit` | `dist.c:1773` | Encodes and sends a link exit signal remotely. | Missing |
| `erts_dsig_send_group_leader` | `dist.c:1832` | Encodes and sends a group leader change signal remotely. | Missing |
| `erts_net_message` | `dist.c:2017` | Main entrypoint for decoding incoming byte streams into distribution signals. | Missing |
| `erts_init_node_tables` | `erl_node_tables.c:1073` | Initializes the hash tables for distribution entries and node names. | Missing |
| `erts_ref_dist_entry` | `erl_node_tables.c:109` | Increments the reference count of a distribution entry. | Missing |
| `erts_sysname_to_connected_dist_entry` | `erl_node_tables.c:341` | Resolves a node name atom to an active distribution channel connection. | Missing |
| `erts_set_dist_entry_connected` | `erl_node_tables.c:733` | Transitions a distribution entry from pending to fully connected. | Missing |
| `erts_get_node_and_dist_references` | `erl_node_tables.c:1281` | Collects debugging references for nodes and distribution connections. | Missing |

## 2. Tracing

### BIFs

| MFA | C Implementation | Purpose | Arinsal Status |
| --- | --- | --- | --- |
| `erts_internal:trace/3` | `erl_bif_trace.c:890` | Sets process-level trace flags natively. | `crates/vm/src/natives/proc.rs:2072` |
| `erts_internal:trace/4` | `erl_bif_trace.c:899` | Similar to trace/3, but targets a specific trace session. | Missing |
| `erts_internal:trace_pattern/3` | `erl_bif_trace.c:303` | Sets call trace patterns on specific MFA functions. | Missing |
| `erts_internal:trace_pattern/4` | `erl_bif_trace.c:315` | Sets call trace patterns restricted to a specific trace session. | Missing |
| `erlang:trace_info/2` | `erl_bif_trace.c:1386` | Retrieves trace settings for a pid, port, or function. | Missing |
| `erts_internal:trace_info/3` | `erl_bif_trace.c:1406` | Retrieves trace settings for a specific trace session. | Missing |
| `erlang:trace_delivered/1` | `erl_bif_trace.c:3900` | Ensures trace messages generated up to this point have been delivered. | Missing |
| `erlang:seq_trace/2` | `erl_bif_trace.c:3025` | Sets sequential tracing flags and tokens. | Missing |
| `erlang:seq_trace_info/1` | `erl_bif_trace.c:3216` | Reads the current sequential trace settings. | Missing |
| `erlang:seq_trace_print/1` | `erl_bif_trace.c:3229` | Prints a user-defined sequential trace message to the tracer. | Missing |
| `erlang:seq_trace_print/2` | `erl_bif_trace.c:3248` | Prints a sequential trace message with a custom token. | Missing |
| `erts_internal:trace_session_create/3` | `erl_bif_trace.c:1232` | Creates a new named trace session (ERTS 27+ feature). | Missing |
| `erts_internal:trace_session_destroy/1` | `erl_bif_trace.c:1279` | Tears down a named trace session. | Missing |
| `erts_trace_cleaner:check/0` | `erl_bif_trace.c:605` | Checks the state of the background trace cleaner process. | Missing |
| `erts_trace_cleaner:send_trace_clean_signal/1` | `erl_bif_trace.c:650` | Sends a signal to purge deferred trace structures. | Missing |

### Non-BIF C Machinery (erl_trace.c, beam_bp.c)

| Function / Component | C Implementation | Purpose | Arinsal Status |
| --- | --- | --- | --- |
| `trace_sched` | `erl_trace.c:703` | Builds and emits scheduling trace events (e.g. `in`, `out`). | Missing |
| `trace_send` | `erl_trace.c:776` | Builds and emits message-sending trace events (`send`). | Missing |
| `trace_send_session` | `erl_trace.c:791` | Same as `trace_send`, scoped to a specific session. | Missing |
| `erts_trace_return_to` | `erl_trace.c:1037` | Builds and emits `return_to` call trace events. | Missing |
| `trace_gc` | `erl_trace.c:1438` | Builds and emits garbage collection events. | Missing |
| `trace_port_receive` | `erl_trace.c:2093` | Builds and emits trace events for port operations. | Missing |
| `erts_generic_breakpoint` | `beam_bp.c:993` | The main execution trap when a patched opcode (e.g., `op_i_generic_breakpoint`) is hit. Handles the trace tuple construction and condition matching. | Missing |
| `erts_set_trace_break` | `beam_bp.c:760` | Patches an instruction to a global or session-specific trace breakpoint. | Missing |
| `erts_set_count_break` | `beam_bp.c:784` | Patches an instruction to a breakpoint counting executions. | Missing |
| `erts_set_time_break` | `beam_bp.c:791` | Patches an instruction to a breakpoint tracking execution time. | Missing |
| `erts_clear_all_breaks` | `beam_bp.c:847` | Removes all breakpoints from patched code. | Missing |
| Tracer modules (`erl_tracer` NIF) | `erl_tracer_nif.c` | Handles forwarding trace events to custom NIF tracer modules (used by `dbg`). | Partially present (`crates/vm/src/natives/nif.rs:402`) |

## 3. Implementation Plan

The following dependency-ordered steps describe how to incrementally implement the missing distribution and tracing capabilities. 

### Phase A: Node Identities and Distribution Setup
1. **Node Tables** (Estimate: S)
   - *Hypothesis:* Arinsal currently maps all remote/local nodes to `"nonode@nohost"`.
   - *Fact:* `node.rs` hardcodes `"nonode@nohost"`.
   - *Action:* Introduce an `ErtsNode` equivalent registry (e.g., in `vm/src/nodes.rs`) to store node atom names, cookies, and network connections.
2. **Distribution Initialization** (Estimate: M)
   - *Fact:* `erlang:setnode/2` is required by the `net_kernel` to initialize the node.
   - *Action:* Implement `setnode/2` to update the node registry and set the node creation ID. Wire `erlang:monitor_node/2,3` to record subscription requests.

### Phase B: Distribution Data Paths
3. **Distribution Controllers** (Estimate: M)
   - *Fact:* Modern OTP uses distribution controllers (`dist_ctrl_*`) to decouple transport streams.
   - *Action:* Add BIFs for `dist_ctrl_get_opt/2`, `dist_ctrl_set_opt/3`, `dist_ctrl_input_handler/2`. Maintain an in-memory queue for controller streams.
4. **Distribution Signals (DSIG)** (Estimate: L)
   - *Fact:* `dist.c` sends and parses d-signals (`erts_net_message`).
   - *Action:* Build the distribution signal encoders and decoders. Translate internal events (links, monitors, exits) into outgoing packet structures, and decode incoming data. Implement `create_dist_channel/3` and `dist_ext_to_term/2`.

### Phase C: Remote Spawns and Asynchronous Capabilities
5. **Asynchronous Spawns** (Estimate: M)
   - *Fact:* `spawn_request` allows spawning remotely without blocking.
   - *Action:* Implement `spawn_request/4` and `dist_spawn_request/4`. Connect them to the DSIG layer for remote dispatch, and handle `spawn_request_abandon/1`.

### Phase D: Basic Tracing
6. **Trace Message Delivery** (Estimate: M)
   - *Fact:* Arinsal sets `trace/3` flags natively but does not emit trace events correctly yet (partially in `nif.rs`).
   - *Action:* Plumb process-level events (e.g., send, receive, spawn, exit) to check the trace flags and build standard Erlang message tuples. Implement `erlang:trace_delivered/1` using a synchronization signal.
7. **Sequential Tracing** (Estimate: S)
   - *Fact:* Tokens must follow messages between processes.
   - *Action:* Add the sequential token to the message/process structures. Implement `seq_trace/2` and print BIFs.

### Phase E: Advanced Tracing & Call Interception
8. **Code Breakpoints** (Estimate: L)
   - *Fact:* Function tracing relies on instruction patching (`beam_bp.c`).
   - *Action:* Introduce a patching mechanism in `beamasm_integration.rs` or the interpreter to hot-swap function entry points with a breakpoint opcode. Implement `trace_pattern/3` to inject these traps.
9. **Trace Sessions** (Estimate: M)
   - *Fact:* ERTS 27+ introduced isolated tracing sessions.
   - *Action:* Implement `trace_session_create/3`, `trace_session_destroy/1`, and update all trace checks to filter by active sessions. Add the `trace_cleaner` BIFs.
