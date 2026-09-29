//! Runtime helper bodies called by BeamAsm generated code.

use arinsal_beamasm::ProcessHeader;
use arinsal_bits::MatchOps;
use arinsal_term::Term;

/// Dispatches a BIF export from the shared export trampoline.
// Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:164-210, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_export_trampoline(
    header: *mut ProcessHeader,
    identity: u64,
) -> u64 {
    if invoke_dispatch_bif(header, identity as usize).is_some() {
        0
    } else {
        1
    }
}

/// Runs a light BIF through the shared BeamAsm fragment.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-471, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_call_light_bif_shared(
    header: *mut ProcessHeader,
    identity: u64,
) -> u64 {
    invoke_dispatch_bif(header, identity as usize).unwrap_or(0)
}

/// Handles an enabled BeamAsm function-entry breakpoint.
// Port of erts/emulator/beam/jit/arm/instr_trace.cpp:62-95, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_breakpoint(
    header: *mut ProcessHeader,
    return_address: u64,
) -> u64 {
    let Some((process, _registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    let Some(function) = crate::native_function_at(return_address as usize) else {
        return 0;
    };
    crate::trace_bp::increment(
        process,
        &function.module,
        &function.function,
        function.arity,
        true,
    );
    let actions = crate::trace::native_call_event(
        process,
        &function.module,
        &function.function,
        function.arity,
    );
    if !actions.is_empty() {
        let frame_words = 4usize.saturating_add(actions.len().saturating_mul(2));
        let old_cp = process.heap.stack_get(0);
        if old_cp.is_none() || !process.heap.reserve_stack(frame_words) {
            crate::native_hooks::set_error(process, "system_limit");
            process.sync_native_header();
            return 0;
        }
        let old_cp = old_cp.expect("checked native continuation");
        let trace_stub =
            arinsal_beamasm::rt::arinsal_enter_native_trace_return as *const () as usize;
        let metadata = [
            crate::proc_create::native_continuation_term(trace_stub),
            old_cp,
            Term::small(return_address as i64).unwrap_or(Term::NIL),
            Term::small(actions.len() as i64).unwrap_or(Term::NIL),
        ];
        for (index, value) in metadata.into_iter().enumerate() {
            process.heap.stack_set(index, value);
        }
        for (index, action) in actions.into_iter().enumerate() {
            let flags = u8::from(action.return_trace) | (u8::from(action.exception_trace) << 1);
            let session = Term::small(action.session as i64).unwrap_or(Term::NIL);
            let flags = Term::small(i64::from(flags)).unwrap_or(Term::NIL);
            process.heap.stack_set(4 + index * 2, session);
            process.heap.stack_set(5 + index * 2, flags);
        }
        process.sync_native_header();
    }
    0
}

/// Completes a traced native return and resumes its saved caller continuation.
// Port of erts/emulator/beam/jit/arm/instr_trace.cpp:152-195, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_native_trace_return(header: *mut ProcessHeader) -> u64 {
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    let Some(saved_caller) = process.heap.stack_get(0) else {
        return 0;
    };
    let Some(function_pc) = process.heap.stack_get(1).and_then(Term::as_small) else {
        return saved_caller.tagged_word();
    };
    let Some(action_count) = process.heap.stack_get(2).and_then(Term::as_small) else {
        return saved_caller.tagged_word();
    };
    let Some(function) = crate::native_function_at(function_pc as usize) else {
        return saved_caller.tagged_word();
    };
    let value = process.x[0];
    for index in 0..usize::try_from(action_count).unwrap_or(0) {
        let session = process
            .heap
            .stack_get(3 + index * 2)
            .and_then(Term::as_small);
        let flags = process
            .heap
            .stack_get(4 + index * 2)
            .and_then(Term::as_small);
        let (Some(session), Some(flags)) = (session, flags) else {
            continue;
        };
        crate::trace::native_return_event(
            process,
            &function,
            crate::trace::NativeTraceAction {
                session: session as u64,
                return_trace: flags & 1 != 0,
                exception_trace: flags & 2 != 0,
            },
            value,
            false,
        );
    }
    let cleanup = 4usize.saturating_add(usize::try_from(action_count).unwrap_or(0) * 2);
    process
        .heap
        .set_stack_pointer(process.header.stop.wrapping_add(cleanup));
    process.sync_native_header();
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    saved_caller.tagged_word()
}

/// Collects from the native heap and stack cursors published by generated code.
// Port of erts/emulator/beam/jit/arm/instr_common.cpp:90-122 and beam_asm_global.cpp:102-140, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_gc_sync(
    header: *mut ProcessHeader,
    scheduler_registers: *mut arinsal_beamasm::SchedulerRegisters,
    need_words: usize,
    live: usize,
    _fcalls: i32,
) -> i32 {
    if scheduler_registers.is_null() {
        return 0;
    }
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    if !std::ptr::eq(registers, scheduler_registers) {
        return 0;
    }
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    // Port of erl_gc.c:1879 and 2072-2080, OTP-29.1.1: collection sizing
    // keeps stack-reserved words in addition to the requested heap allocation.
    let need_words = need_words.saturating_add(arinsal_term::CP_WORDS);
    if process.ensure(need_words, live).is_err() {
        crate::native_hooks::set_error(process, "system_limit");
    }
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    for (destination, term) in registers
        .x_reg_array
        .iter_mut()
        .zip(process.x.iter())
        .take(6)
    {
        *destination = crate::native_hooks::raw(*term);
    }
    process.sync_native_header();
    0
}

fn invoke_dispatch_bif(header: *mut ProcessHeader, identity: usize) -> Option<u64> {
    let (process, registers) = crate::native_hooks::process_and_registers(header)?;
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    if identity == arinsal_beamasm::dispatch::SEND_DISPATCH_IDENTITY {
        process.header.i = arinsal_beamasm::dispatch::SEND_UNPORTED as *const u8 as *const _;
        process.header.freason = 1 << 10;
        process.sync_native_header();
        return None;
    }
    let export = crate::beamasm_integration::export_dispatch(identity)?;
    if matches!(
        export.class,
        arinsal_loader::ImportClass::Native | arinsal_loader::ImportClass::Dynamic
    ) {
        process.reductions = process.header.fcalls;
        process.header.arity = export.arity;
        process.header.i = identity as *const u8 as *const _;
        process.header.freason = 1 << 10;
        process.sync_native_header();
        return None;
    }
    let (bif, arity) = crate::beamasm_integration::dispatch_bif(identity)?;
    process.reductions = process.header.fcalls;
    let arity = usize::from(arity);
    if arity > process.x.len() {
        crate::native_hooks::set_error(process, "system_limit");
        return Some(0);
    }
    for (destination, raw) in process
        .x
        .iter_mut()
        .zip(registers.x_reg_array.iter().copied())
        .take(6)
    {
        *destination = crate::native_hooks::from_raw(raw);
    }
    let args = registers.x_reg_array[..arity]
        .iter()
        .copied()
        .map(crate::native_hooks::from_raw)
        .collect::<Vec<_>>();
    let result = crate::calls::call_bif(&mut process.heap, bif, &args);
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    match result {
        Ok(value) => {
            let value = crate::native_hooks::raw(value);
            process.x[0] = value_term(value);
            publish_dispatch_x(process, registers);
            process.sync_native_header();
            Some(value)
        }
        Err(error) => {
            set_light_bif_error(process, error);
            publish_dispatch_x(process, registers);
            process.sync_native_header();
            Some(0)
        }
    }
}

fn publish_dispatch_x(
    process: &crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
) {
    for (destination, term) in registers
        .x_reg_array
        .iter_mut()
        .zip(process.x.iter())
        .take(6)
    {
        *destination = crate::native_hooks::raw(*term);
    }
}

fn value_term(value: u64) -> Term {
    crate::native_hooks::from_raw(value)
}

fn set_light_bif_error(process: &mut crate::Process, error: arinsal_bifs::BifError) {
    use arinsal_bifs::{BifError, Class};
    let (class, reason) = match error {
        BifError::Badarg { .. } => (1, crate::signals::atom("badarg")),
        BifError::Badarith => (1, crate::signals::atom("badarith")),
        BifError::SystemLimit => (1, crate::signals::atom("system_limit")),
        BifError::Error(reason) => (1, reason),
        BifError::Raise { class, reason, .. } => (
            match class {
                Class::Error => 1,
                Class::Exit => 2,
                Class::Throw => 3,
            },
            reason,
        ),
        BifError::Unsupported(_) => (1, crate::signals::atom("undef")),
    };
    process.header.freason = class;
    process.header.fvalue = crate::native_hooks::raw(reason);
}

/// Leaves an uncaught native exception for the VM scheduler to resume.
pub extern "C" fn arinsal_beamasm_exception_resolver(
    _header: *mut ProcessHeader,
    _registers: *mut arinsal_beamasm::SchedulerRegisters,
    _stack: *mut u64,
) -> usize {
    0
}

/// Resolves a fun call that missed the local-dispatch fast path.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:1307-1365
// (beam_jit_handle_unloaded_fun) and instr_fun.cpp:77-140, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_fun_resolver(
    header: *mut ProcessHeader,
    fun_raw: u64,
    arity: u32,
) -> usize {
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    let fun = crate::native_hooks::from_raw(fun_raw);
    let view = crate::native_hooks::fun_view(fun);
    let unported = crate::beamasm_integration::call_fun_unported_entry();
    match view {
        Some(arinsal_term::FunRef::Local { entry, .. }) => {
            if u32::from(entry.arity) != arity {
                crate::native_hooks::set_error(process, "badarity");
                publish_dispatch_x(process, registers);
                process.sync_native_header();
                return 0;
            }
            if let Some(target) = entry.get_dispatch_target(0) {
                publish_dispatch_x(process, registers);
                process.sync_native_header();
                return target;
            }
            process.header.arity = arity.min(u8::MAX as u32) as u8;
            if let Some(slot) = process.x.get_mut(arity as usize) {
                *slot = fun;
            }
            publish_dispatch_x(process, registers);
            process.sync_native_header();
            if unported == 0 {
                crate::native_hooks::set_error(process, "badfun");
                process.sync_native_header();
                return 0;
            }
            unported
        }
        Some(arinsal_term::FunRef::Export { entry }) => {
            if u32::from(entry.arity) != arity {
                crate::native_hooks::set_error(process, "badarity");
                publish_dispatch_x(process, registers);
                process.sync_native_header();
                return 0;
            }
            let Some(module) = arinsal_term::global_atoms().text(entry.module) else {
                crate::native_hooks::set_error(process, "badfun");
                publish_dispatch_x(process, registers);
                process.sync_native_header();
                return 0;
            };
            let Some(function) = arinsal_term::global_atoms().text(entry.function) else {
                crate::native_hooks::set_error(process, "badfun");
                publish_dispatch_x(process, registers);
                process.sync_native_header();
                return 0;
            };
            if let Some(target) = crate::beamasm_integration::native_target_for(
                module.as_ref(),
                function.as_ref(),
                entry.arity,
            ) {
                publish_dispatch_x(process, registers);
                process.sync_native_header();
                return target;
            }
            if let Some(native) =
                crate::native_function_for(module.as_ref(), function.as_ref(), entry.arity)
            {
                publish_dispatch_x(process, registers);
                process.sync_native_header();
                return native.start;
            }
            process.header.arity = arity.min(u8::MAX as u32) as u8;
            if let Some(slot) = process.x.get_mut(arity as usize) {
                *slot = fun;
            }
            publish_dispatch_x(process, registers);
            process.sync_native_header();
            if unported == 0 {
                crate::native_hooks::set_error(process, "undef");
                process.sync_native_header();
                return 0;
            }
            unported
        }
        None => {
            crate::native_hooks::set_error(process, "badfun");
            publish_dispatch_x(process, registers);
            process.sync_native_header();
            0
        }
    }
}

/// Builds a map or applies staged key/value updates to one.
// Port of erts/emulator/beam/jit/arm/instr_map.cpp:125-149,465-633, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_map_new(
    header: *mut ProcessHeader,
    source: u64,
    _registers: u64,
    live: u64,
    count: u64,
) -> u64 {
    arinsal_beamasm_map_change(header, source, live, count, false, false)
}

/// Applies associative updates to a staged list of key/value pairs.
pub extern "C" fn arinsal_beamasm_map_assoc(
    header: *mut ProcessHeader,
    source: u64,
    _registers: u64,
    live: u64,
    count: u64,
) -> u64 {
    arinsal_beamasm_map_change(header, source, live, count, false, true)
}

/// Applies exact updates to a staged list of key/value pairs.
pub extern "C" fn arinsal_beamasm_map_exact(
    header: *mut ProcessHeader,
    source: u64,
    _registers: u64,
    live: u64,
    count: u64,
) -> u64 {
    arinsal_beamasm_map_change(header, source, live, count, true, true)
}

fn arinsal_beamasm_map_change(
    header: *mut ProcessHeader,
    source: u64,
    live: u64,
    count: u64,
    exact: bool,
    update: bool,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    let Ok(count) = usize::try_from(count) else {
        return 0;
    };
    let Ok(live) = usize::try_from(live) else {
        return 0;
    };
    // Stage source at X6-1 spill space is already used for pairs at X6+; keep source
    // in the live X registers so GC during ensure relocates it. The emitter stages
    // `{key,value}` pairs at X6.. and passes `live` covering X0..X{live-1} plus those.
    let source_slot = 6 + count * 2;
    if source_slot >= registers.x_reg_array.len() {
        return 0;
    }
    registers.x_reg_array[source_slot] = source;
    let root_live = live.max(source_slot + 1);
    if process.x.len() < root_live {
        let mut x = process.x.to_vec();
        x.resize(root_live, arinsal_term::Term::NIL);
        process.x = x.into_boxed_slice();
    }
    for (i, slot) in registers.x_reg_array[..root_live].iter().enumerate() {
        process.x[i] = crate::native_hooks::from_raw(*slot);
    }
    let existing = if update {
        arinsal_maps::size(crate::native_hooks::from_raw(source)).unwrap_or(0)
    } else {
        0
    };
    // put_many rebuilds the whole map; reserve space for existing entries plus updates.
    // Port of erts/emulator/beam/erl_map.c:261-365 (erts_maps_update), OTP-29.1.1.
    let Some(mut words) = existing
        .checked_add(count)
        .and_then(|n| n.checked_mul(4))
        .and_then(|n| n.checked_add(16))
    else {
        return 0;
    };
    let result = loop {
        if process.ensure(words, root_live).is_err() {
            crate::native_hooks::set_error(process, "system_limit");
            registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
            return 0;
        }
        registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
        let source_term = process.x[source_slot];
        let mut pairs = Vec::with_capacity(count);
        for index in 0..count {
            let key = process.x[6 + index * 2];
            let value = process.x[7 + index * 2];
            pairs.push((key, value));
        }
        let attempt = if update {
            arinsal_maps::put_many(source_term, &pairs, exact, &mut process.heap)
        } else {
            arinsal_maps::from_pairs(&pairs, &mut process.heap)
        };
        match attempt {
            Err(arinsal_maps::MapError::HeapFull { need_words }) => {
                words = words.max(need_words);
            }
            other => {
                for (slot, term) in registers.x_reg_array[..root_live]
                    .iter_mut()
                    .zip(process.x.iter())
                {
                    *slot = crate::native_hooks::raw(*term);
                }
                break other;
            }
        }
    };
    process.sync_native_header();
    match result {
        Ok(term) => crate::native_hooks::raw(term),
        Err(arinsal_maps::MapError::Badkey(_)) if exact => 0,
        Err(arinsal_maps::MapError::Badmap(_)) => {
            crate::native_hooks::set_error(process, "badmap");
            0
        }
        Err(arinsal_maps::MapError::HeapFull { .. }) => {
            crate::native_hooks::set_error(process, "system_limit");
            0
        }
        Err(_) => {
            crate::native_hooks::set_error(process, "badarg");
            0
        }
    }
}

/// Generic fallback lookup for non-flatmap keys.
pub extern "C" fn arinsal_beamasm_map_get(
    header: *mut ProcessHeader,
    map: u64,
    key: u64,
    _hash: u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    let result = arinsal_maps::get(
        crate::native_hooks::from_raw(map),
        crate::native_hooks::from_raw(key),
    );
    for (destination, term) in registers
        .x_reg_array
        .iter_mut()
        .zip(process.x.iter())
        .take(6)
    {
        *destination = crate::native_hooks::raw(*term);
    }
    process.sync_native_header();
    match result {
        Ok(Some(value)) => crate::native_hooks::raw(value),
        Ok(None) | Err(arinsal_maps::MapError::Badkey(_)) => 0,
        Err(arinsal_maps::MapError::Badmap(_)) => {
            crate::native_hooks::set_error(process, "badmap");
            0
        }
        Err(_) => {
            crate::native_hooks::set_error(process, "badarg");
            0
        }
    }
}

/// Generic fallback for a batch of map lookups staged at X6.
pub extern "C" fn arinsal_beamasm_map_get_elements(
    header: *mut ProcessHeader,
    map: u64,
    _registers: u64,
    _live: u64,
    count: u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    let Ok(count) = usize::try_from(count) else {
        return 0;
    };
    for index in 0..count {
        let key = crate::native_hooks::from_raw(registers.x_reg_array[6 + index * 3]);
        let result = arinsal_maps::get(crate::native_hooks::from_raw(map), key);
        let Ok(Some(value)) = result else {
            return 0;
        };
        registers.x_reg_array[7 + index * 3] = crate::native_hooks::raw(value);
    }
    process.sync_native_header();
    1
}

/// Completes one construction segment that was not emitted inline.
pub extern "C" fn arinsal_beamasm_bs_construct(
    header: *mut ProcessHeader,
    _operation: u64,
    _value: u64,
    _size: u64,
    _unit: u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    for (destination, term) in registers
        .x_reg_array
        .iter_mut()
        .zip(process.x.iter())
        .take(6)
    {
        *destination = crate::native_hooks::raw(*term);
    }
    process.sync_native_header();
    0
}

/// Records the binary construction failure as a BEAM `badarg` exception.
pub extern "C" fn arinsal_beamasm_bs_construct_error(
    header: *mut ProcessHeader,
    _info: u32,
    _value: u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    crate::native_hooks::set_error(process, "badarg");
    for (destination, term) in registers
        .x_reg_array
        .iter_mut()
        .zip(process.x.iter())
        .take(6)
    {
        *destination = crate::native_hooks::raw(*term);
    }
    process.sync_native_header();
    0
}

/// Runs the common BeamAsm match-context operations used by bit syntax emitters.
// Port of erts/emulator/beam/jit/arm/instr_bs.cpp:134-255, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_bs_match(
    header: *mut ProcessHeader,
    op: u32,
    context: u64,
    value: u64,
    _unit: u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    let context = crate::native_hooks::from_raw(context);
    let value = crate::native_hooks::from_raw(value);
    let result = match op {
        0 => {
            let live = value
                .as_small()
                .and_then(|n| usize::try_from(n).ok())
                .unwrap_or(6);
            let live = live.min(process.x.len());
            process.ensure(2, live).ok().and_then(|()| {
                arinsal_bits::start_match(context, &mut process.heap)
                    .ok()
                    .flatten()
            })
        }
        3 => process
            .ensure(2, process.gc_live)
            .ok()
            .and_then(|()| arinsal_bits::get_position(context, &mut process.heap).ok()),
        4 => arinsal_bits::set_position_term(context, value).then_some(Term::NIL),
        6 => {
            let bits = value
                .as_small()
                .and_then(|n| usize::try_from(n).ok())
                .and_then(|n| {
                    usize::try_from(_unit)
                        .ok()
                        .and_then(|unit| n.checked_mul(unit))
                });
            bits.and_then(|bits| {
                process
                    .ensure(4, process.gc_live)
                    .ok()
                    .and_then(|()| context.get_binary(bits, &mut process.heap).ok().flatten())
            })
        }
        10 => {
            let live = value
                .as_small()
                .and_then(|n| usize::try_from(n).ok())
                .unwrap_or(6);
            process
                .ensure(2, live.min(process.x.len()))
                .ok()
                .and_then(|()| context.get_tail(&mut process.heap).ok())
        }
        _ => None,
    };
    for (destination, term) in registers
        .x_reg_array
        .iter_mut()
        .zip(process.x.iter())
        .take(6)
    {
        *destination = crate::native_hooks::raw(*term);
    }
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    process.sync_native_header();
    result.map(crate::native_hooks::raw).unwrap_or(0)
}
