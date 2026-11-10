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

// g_proc_sched. Port of erl_gc.c:3756 (error_logger report),
// utils.c:802 (`do_send_logger_message`) and utils.c:885
// (`send_error_term_to_logger`), OTP-29.1.1.
fn report_max_heap(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    limit: MaxHeap,
    used: u64,
) {
    let format = "     Process:            ~p ~n     Context:            maximum heap size reached~n     Max Heap Size:      ~p~n     Total Heap Size:    ~p~n     Kill:               ~p~n     Error Logger:       ~p~n     Message Queue Len:  ~p~n     GC Info:            ~p~n     Stacktrace:         ~p~n";
    eprintln!(
        "     Process:            {:?}\n     Context:            maximum heap size reached\n     Max Heap Size:      {}\n     Total Heap Size:    {used}\n     Kill:               {}\n     Error Logger:       true\n     Message Queue Len:  {}\n     GC Info:            []\n     Stacktrace:         []",
        ctx.pid(),
        limit.size,
        limit.kill,
        process.inbox.len()
    );
    let Some(runtime) = process.runtime else {
        return;
    };
    let logger = runtime
        .reg
        .whereis_proc_str("logger")
        .or_else(|| runtime.reg.whereis_proc_str("error_logger"));
    let Some(logger) = logger else {
        return;
    };
    let Some(pid) = ctx.pid().to_term() else {
        return;
    };
    let group_leader = process.group_leader.and_then(Pid::to_term);
    let bool_atom = |on: bool| {
        Term::atom(if on {
            arinsal_term::atoms::TRUE
        } else {
            arinsal_term::atoms::FALSE
        })
    };
    let built = (|| -> Result<Term, VmError> {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        let mut builder = TermBuilder::new(&mut heap);
        let format = builder
            .list_from_iter(
                format
                    .bytes()
                    .map(|byte| Term::small(i64::from(byte)).unwrap()),
            )
            .map_err(|error| VmError::Unsupported(format!("logger format: {error:?}")))?;
        let args = [
            pid,
            Term::small(limit.size as i64).unwrap_or(Term::NIL),
            Term::small(used as i64).unwrap_or(Term::NIL),
            bool_atom(limit.kill),
            Term::atom(arinsal_term::atoms::TRUE),
            Term::small(process.inbox.len() as i64).unwrap_or(Term::NIL),
            Term::NIL,
            Term::NIL,
        ];
        let args = builder
            .list_from_iter(args)
            .map_err(|error| VmError::Unsupported(format!("logger args: {error:?}")))?;
        // Port of erts/emulator/beam/utils.c:773 (`do_send_logger_message`), OTP-29.1.1:
        // `#{error_logger => #{emulator => true, tag => error}, gl => GL, pid => Pid, time => Us}`.
        let micros = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_micros() as i64);
        let el_tag = builder
            .flatmap_from_pairs(&[
                (
                    Term::atom(arinsal_term::atoms::EMULATOR),
                    Term::atom(arinsal_term::atoms::TRUE),
                ),
                (
                    Term::atom(arinsal_term::atoms::TAG),
                    Term::atom(arinsal_term::atoms::ERROR),
                ),
            ])
            .map_err(|error| VmError::Unsupported(format!("logger tag map: {error:?}")))?;
        let mut pairs = vec![
            (Term::atom(arinsal_term::atoms::ERROR_LOGGER), el_tag),
            (
                Term::atom(arinsal_term::atoms::TIME),
                Term::small(micros).unwrap_or(Term::NIL),
            ),
        ];
        if let Some(gl) = group_leader {
            pairs.push((crate::atom_cache::put("gl"), gl));
        }
        pairs.push((Term::atom(arinsal_term::atoms::PID), pid));
        let meta = builder
            .flatmap_from_pairs(&pairs)
            .map_err(|error| VmError::Unsupported(format!("logger metadata: {error:?}")))?;
        builder
            .tuple(&[
                Term::atom(arinsal_term::atoms::LOG),
                Term::atom(arinsal_term::atoms::ERROR),
                format,
                args,
                meta,
            ])
            .map_err(|error| VmError::Unsupported(format!("logger message: {error:?}")))
    })();
    if let Ok(term) = built
        && let Ok(message) = Message::copy_from(term)
    {
        let _ = ctx.send(logger, message);
    }
}
