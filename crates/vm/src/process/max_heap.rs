use super::*;

/// Port of erts/emulator/beam/erl_gc.c (ERTS_ABANDON_HEAP_COST), OTP-29.1.1.
pub(super) const ABANDON_HEAP_COST: i32 = 10;

/// `max_heap_size` flag. Size 0 disables the check, matching `MAX_HEAP_SIZE_GET`.
///
/// g_proc_sched. Port of erts/emulator/beam/erl_gc.c:3824 (`erts_max_heap_size`), OTP-29.1.1.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MaxHeap {
    pub size: u64,
    pub kill: bool,
    pub log: bool,
    pub include_shared_binaries: bool,
    pub reported: bool,
}

impl Default for MaxHeap {
    fn default() -> Self {
        Self {
            size: 0,
            kill: true,
            log: true,
            include_shared_binaries: false,
            reported: false,
        }
    }
}

impl Process {
    /// Whether this process has a `max_heap_size` limit. The peak is tracked only then.
    pub(super) fn max_heap_limited(&self) -> bool {
        self.cold
            .as_ref()
            .is_some_and(|cold| cold.max_heap.size != 0)
    }
}

// g_proc_sched. Port of erl_gc.c:3730 (`has_reached_max_heap_size`) and
// erl_gc.c:3741 (`reached_max_heap_size`), OTP-29.1.1.
#[inline(always)]
pub(super) fn heap_limit_kills(process: &mut Process, ctx: &mut RunCtx<'_, Message>) -> bool {
    if process
        .cold
        .as_ref()
        .is_none_or(|cold| cold.max_heap.size == 0)
    {
        return false;
    }
    heap_limit_check(process, ctx)
}

#[inline(never)]
fn heap_limit_check(process: &mut Process, ctx: &mut RunCtx<'_, Message>) -> bool {
    let snapshot = {
        // Port of erts/emulator/beam/erl_process.h (`p->max_heap_size`), OTP-29.1.1: the limit
        // is a field of the process itself, so only the process reads or writes it.
        let Some(mut limit) = process.cold.as_ref().map(|cold| cold.max_heap) else {
            return false;
        };
        if limit.size == 0 {
            return false;
        }
        // Only a collection checks the limit (`garbage_collect`), so judge the size seen there.
        let mut used = std::mem::take(&mut process.max_heap_peak) as u64;
        if limit.include_shared_binaries {
            used = used.saturating_add(off_heap_binary_words(process) as u64);
        }
        if used <= limit.size {
            return false;
        }
        let log = limit.log && !limit.reported;
        if log {
            limit.reported = true;
            process.cold_mut().max_heap = limit;
        }
        (log, limit.kill, limit, used)
    };
    let (log, kill, limit, used) = snapshot;
    if log {
        report_max_heap(process, ctx, limit, used);
    }
    kill
}

pub(super) fn off_heap_binary_words(process: &Process) -> usize {
    let mut seen = HashSet::new();
    let mut bytes = HashMap::<usize, usize>::new();
    let mut stack = Vec::new();
    // Only the `arity` registers a switched-out process saved are roots; a completed process
    // has released its register file.
    for term in process.x[..switched_out_live(process)]
        .iter()
        .copied()
        .chain(process.inbox.iter().copied())
    {
        stack.push(term);
    }
    if let Some(dictionary) = &process.dictionary {
        for (key, value) in dictionary.entries() {
            stack.push(key);
            stack.push(value);
        }
    }
    for index in 0..process.heap.stack_words() {
        if let Some(term) = process.heap.stack_get(index) {
            stack.push(term);
        }
    }
    while let Some(term) = stack.pop() {
        if !term.is_pointer() {
            continue;
        }
        // SAFETY: The term is a live pointer on this process heap. The bit
        // pattern is an identity for the DAG walk, not a dereference.
        let bits = unsafe { term.raw_bits() };
        if !seen.insert(bits) {
            continue;
        }
        // SAFETY: The owning heap stays live for this walk; no collection runs.
        if let Some(binary) = unsafe { term.binary_ref() } {
            if binary.bytes().len() > 64 {
                bytes
                    .entry(binary.bytes().as_ptr() as usize)
                    .or_insert(binary.bytes().len());
            }
            continue;
        }
        // SAFETY: The cons cell borrows this live heap; no collection runs.
        if let Some((head, tail)) = unsafe { term.cons_ref() } {
            stack.push(head);
            stack.push(tail);
            continue;
        }
        // SAFETY: The tuple borrows this live heap; no collection runs.
        if let Some(tuple) = unsafe { term.tuple_ref() } {
            for index in 0..tuple.len() {
                if let Some(element) = tuple.get(index) {
                    stack.push(element);
                }
            }
            continue;
        }
        // SAFETY: The map borrows this live heap; no collection runs.
        if let Some(map) = unsafe { term.flatmap_ref() } {
            for (key, value) in map.iter() {
                stack.push(key);
                stack.push(value);
            }
            continue;
        }
        // SAFETY: The fun borrows this live heap; no collection runs.
        if let Some(fun) = unsafe { term.fun_ref() } {
            for index in 0..fun.num_free() {
                if let Some(value) = fun.free(index) {
                    stack.push(value);
                }
            }
        }
    }
    bytes
        .values()
        .fold(0, |sum, len| sum.saturating_add(len.div_ceil(8)))
}

// g_proc_sched. Port of erl_gc.c:3756 (error_logger report in `reached_max_heap_size`),
// OTP-29.1.1.
fn report_max_heap(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    limit: MaxHeap,
    used: u64,
) {
    let Some(runtime) = process.runtime else {
        return;
    };
    let Some(pid) = ctx.pid().to_term() else {
        return;
    };
    let node_name = {
        let nodes = crate::node_tables::lock();
        crate::node_tables::is_alive().then(|| nodes.local_identity().0.to_owned())
    };
    let mut format = String::from("     Process:            ~p ");
    if node_name.is_some() {
        format.push_str("on node ~p");
    }
    format.push_str("~n     Context:            maximum heap size reached~n     Max Heap Size:      ~p~n     Total Heap Size:    ~p~n     Kill:               ~p~n     Error Logger:       ~p~n     Message Queue Len:  ~p~n     GC Info:            ~p~n     Stacktrace:         ~p~n");
    let group_leader = process
        .group_leader
        .and_then(Pid::to_term)
        .unwrap_or(Term::NIL);
    let bool_atom = |on: bool| {
        Term::atom(if on {
            arinsal_term::atoms::TRUE
        } else {
            arinsal_term::atoms::FALSE
        })
    };
    // `msg = erts_process_gc_info(...)` and `erts_build_stacktrace(&hfact, p, 0,
    // erts_backtrace_depth, 1)`.
    let gc_info = crate::natives::proc::process_gc_info(process).unwrap_or(Term::NIL);
    let depth = crate::stacktrace::runtime_backtrace_depth(process, 8);
    let stacktrace = crate::stacktrace::build(process, None, depth).unwrap_or(Term::NIL);
    let built = (|| -> Result<Term, VmError> {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        let mut builder = TermBuilder::new(&mut heap);
        let mut args = vec![pid];
        if let Some(node_name) = node_name {
            args.push(Term::atom(
                arinsal_term::global_atoms()
                    .intern(&node_name)
                    .map_err(|error| VmError::Unsupported(format!("node atom: {error:?}")))?,
            ));
        }
        args.extend([
            Term::small(limit.size as i64).unwrap_or(Term::NIL),
            Term::small(used as i64).unwrap_or(Term::NIL),
            bool_atom(limit.kill),
            Term::atom(arinsal_term::atoms::TRUE),
            Term::small(process.inbox.len() as i64).unwrap_or(Term::NIL),
            gc_info,
            stacktrace,
        ]);
        builder
            .list_from_iter(args)
            .map_err(|error| VmError::Unsupported(format!("logger args: {error:?}")))
    })();
    if let Ok(args) = built {
        crate::utils::send_error_term_to_logger(runtime, ctx.pid(), group_leader, &format, args);
    }
}
