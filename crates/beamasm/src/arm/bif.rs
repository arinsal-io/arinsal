//! BIF, export, and apply call emission for BeamAsm modules.

use arinsal_a64::enc::{Cond, Gpr};
use std::sync::OnceLock;

use crate::module::{ArgVal, BeamModuleAssembler, ModuleError};
use crate::rt::addr;
use crate::{Update, emit_enter_runtime, emit_leave_runtime};

pub use arinsal_term::ErtsCodeMfa;

/// `erlang:load_nif/2`, passed to `raise_exception_shared` when the loader returns an error.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:1033-1060, OTP-29.1.1.
pub(crate) static LOAD_NIF_MFA: ErtsCodeMfa = ErtsCodeMfa {
    module: arinsal_term::Term::atom(arinsal_term::atoms::ERLANG).word(),
    function: arinsal_term::Term::atom(arinsal_term::atoms::LOAD_NIF).word(),
    arity: 2,
};

/// Static BIF descriptor stored by `emit_int_div_rem_body_shared` before calling its helper.
// Port of erts/emulator/beam/jit/arm/instr_arith.cpp:740-875, OTP-29.1.1.
pub static ERLANG_DIV_MFA: ErtsCodeMfa = ErtsCodeMfa {
    module: arinsal_term::Term::atom(arinsal_term::atoms::ERLANG).word(),
    function: arinsal_term::Term::atom(arinsal_term::atoms::DIV).word(),
    arity: 2,
};

/// Static BIF descriptor for the remainder instructions.
// Port of erts/emulator/beam/jit/arm/instr_arith.cpp:740-875, OTP-29.1.1.
pub static ERLANG_REM_MFA: ErtsCodeMfa = ErtsCodeMfa {
    module: arinsal_term::Term::atom(arinsal_term::atoms::ERLANG).word(),
    function: arinsal_term::Term::atom(arinsal_term::atoms::REM).word(),
    arity: 2,
};

macro_rules! arith_mfa {
    ($name:ident, $function:ident, $arity:literal) => {
        pub static $name: ErtsCodeMfa = ErtsCodeMfa {
            module: arinsal_term::Term::atom(arinsal_term::atoms::ERLANG).word(),
            function: arinsal_term::Term::atom(arinsal_term::atoms::$function).word(),
            arity: $arity,
        };
    };
}

arith_mfa!(ERLANG_PLUS_MFA, PLUS, 2);
arith_mfa!(ERLANG_MINUS_MFA, MINUS, 2);
arith_mfa!(ERLANG_TIMES_MFA, TIMES, 2);
arith_mfa!(ERLANG_BAND_MFA, BAND, 2);
arith_mfa!(ERLANG_BOR_MFA, BOR, 2);
arith_mfa!(ERLANG_BXOR_MFA, BXOR, 2);
arith_mfa!(ERLANG_BNOT_MFA, BNOT, 1);
arith_mfa!(ERLANG_NEGATE_MFA, MINUS, 1);
arith_mfa!(ERLANG_BSL_MFA, BSL, 2);
arith_mfa!(ERLANG_BSR_MFA, BSR, 2);
arith_mfa!(ERLANG_DIV_2_MFA, DIV_2, 2);

fn guard_mfas() -> &'static [ErtsCodeMfa; 14] {
    static MFAS: OnceLock<[ErtsCodeMfa; 14]> = OnceLock::new();
    MFAS.get_or_init(|| {
        let module = arinsal_term::Term::atom(arinsal_term::atoms::ERLANG).word();
        let function = |name| {
            arinsal_term::Term::atom(
                arinsal_term::global_atoms()
                    .get(name)
                    .unwrap_or_else(|| panic!("predefined BIF atom {name} is missing")),
            )
            .word()
        };
        [
            ErtsCodeMfa {
                module,
                function: function("element"),
                arity: 2,
            },
            ErtsCodeMfa {
                module,
                function: function("hd"),
                arity: 1,
            },
            ErtsCodeMfa {
                module,
                function: function("tl"),
                arity: 1,
            },
            ErtsCodeMfa {
                module,
                function: function("bit_size"),
                arity: 1,
            },
            ErtsCodeMfa {
                module,
                function: function("byte_size"),
                arity: 1,
            },
            ErtsCodeMfa {
                module,
                function: function("map_size"),
                arity: 1,
            },
            ErtsCodeMfa {
                module,
                function: function("tuple_size"),
                arity: 1,
            },
            ErtsCodeMfa {
                module,
                function: function("map_get"),
                arity: 2,
            },
            // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:278-299, OTP-29.1.1:
            // `i_length` raises with this explicit `bif_mfa` when the list is improper.
            ErtsCodeMfa {
                module,
                function: function("length"),
                arity: 1,
            },
            ErtsCodeMfa {
                module,
                function: function("is_map_key"),
                arity: 2,
            },
            // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp (emit_handle_not_error,
            // emit_handle_and_error, emit_handle_or_error: `static ErtsCodeMFA mfa`), OTP-29.1.1.
            ErtsCodeMfa {
                module,
                function: function("not"),
                arity: 1,
            },
            ErtsCodeMfa {
                module,
                function: function("and"),
                arity: 2,
            },
            ErtsCodeMfa {
                module,
                function: function("or"),
                arity: 2,
            },
            // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:1084-1087
            // (emit_handle_node_error), OTP-29.1.1.
            ErtsCodeMfa {
                module,
                function: function("node"),
                arity: 1,
            },
        ]
    })
}

/// Stable MFA addresses for the inline guard BIFs that raise `badarg`.
// Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:52-56, OTP-29.1.1.
pub fn guard_bif_mfa(index: usize) -> Option<usize> {
    // Indexes: 0 element, 1 hd, 2 tl, 3 bit_size, 4 byte_size, 5 map_size, 6 tuple_size,
    // 7 map_get, 8 length, 9 is_map_key, 10 not, 11 and, 12 or, 13 node.
    let mfa = guard_mfas().get(index)?;
    Some(std::ptr::from_ref(mfa) as usize)
}

/// Returns the static MFA used for an arithmetic slow-path operation.
pub fn arithmetic_bif_mfa(op: u32) -> Option<usize> {
    let mfa = match op {
        0 => &ERLANG_PLUS_MFA,
        1 => &ERLANG_MINUS_MFA,
        2 => &ERLANG_TIMES_MFA,
        3 | 14 => &ERLANG_DIV_MFA,
        4 => &ERLANG_REM_MFA,
        5 => &ERLANG_BAND_MFA,
        6 => &ERLANG_BOR_MFA,
        7 => &ERLANG_BXOR_MFA,
        8 => &ERLANG_BNOT_MFA,
        9 => &ERLANG_NEGATE_MFA,
        10 => &ERLANG_BSL_MFA,
        11 => &ERLANG_BSR_MFA,
        12 => &ERLANG_DIV_2_MFA,
        _ => return None,
    };
    Some(std::ptr::from_ref(mfa) as usize)
}

/// Decodes the MFA pointer passed to the exception resolver.
// Port of erts/emulator/beam/beam_common.c (`save_stacktrace` reads `bif_mfa`), OTP-29.1.1.
#[allow(unsafe_code)]
pub fn static_bif_mfa(info: u64) -> Option<(arinsal_term::Atom, arinsal_term::Atom, u8)> {
    let info = usize::try_from(info).ok()?;
    if info == 0 || !info.is_multiple_of(core::mem::align_of::<ErtsCodeMfa>()) {
        return None;
    }
    // SAFETY: the JIT passes only live ErtsCodeMfa addresses from export, arithmetic, and
    // guard callsites, matching handle_error's bif_mfa pointer contract.
    let mfa = unsafe { (info as *const ErtsCodeMfa).read() };
    let atom = |word: u64| (word & 0x3f == 0x0b).then_some(arinsal_term::Atom((word >> 6) as u32));
    Some((
        atom(mfa.module)?,
        atom(mfa.function)?,
        u8::try_from(mfa.arity).ok()?,
    ))
}

/// Code-index constants and the export entry (`Export`), shared with the term crate whose
/// export funs point at the same entries.
// Port of erts/emulator/beam/code_ix.h:72-95 and erts/emulator/beam/export.h:39-75, OTP-29.1.1.
pub use arinsal_term::{
    ERTS_ADDRESSV_SIZE, ERTS_NUM_CODE_IX, ERTS_SAVE_CALLS_CODE_IX, EXPORT_INFO_OFFSET,
    EXPORT_MFA_OFFSET, ExportEntry,
};
/// Byte offset of `Export.info.mfa.arity` (a word; its low byte on little-endian targets).
// Port of erts/emulator/beam/export.h:69-86 (Export.info.mfa.arity), OTP-29.1.1.
pub const EXPORT_ARITY_OFFSET: u32 =
    EXPORT_MFA_OFFSET + core::mem::offset_of!(arinsal_term::ErtsCodeMfa, arity) as u32;
/// Byte offset of [`ExportEntry::is_bif_traced`].
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:391, OTP-29.1.1.
pub const EXPORT_IS_BIF_TRACED_OFFSET: u32 =
    core::mem::offset_of!(ExportEntry, is_bif_traced) as u32;
/// Byte offset of [`ExportEntry::bif_number`] (a 32-bit signed index, -1 for a non-BIF).
// Port of erts/emulator/beam/export.h:55 (Export.bif_number), OTP-29.1.1.
pub const EXPORT_BIF_NUMBER_OFFSET: u32 = core::mem::offset_of!(ExportEntry, bif_number) as u32;
const _: () = assert!(EXPORT_BIF_NUMBER_OFFSET.is_multiple_of(4));

const E: Gpr = Gpr::x(20);
/// The process's code index (`active_code_ix`), loaded on every entry into native code.
const ACTIVE_CODE_IX: Gpr = Gpr::x(24);

impl BeamModuleAssembler {
    /// Loads the current module's NIF library and resumes this instruction after a permission
    /// yield.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:1033-1060 (emit_i_load_nif), OTP-29.1.1.
    pub fn emit_i_load_nif(&mut self) -> Result<(), ModuleError> {
        let entry = self.code.new_label();
        let current = self.code.new_label();
        self.code.bind(entry)?;
        self.code.bind(current)?;

        let update = Update::HEAP_ALLOC.union(Update::X_REGS);
        emit_enter_runtime(&mut self.code, 2, update)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(0), Gpr::x(21)))?;
        self.code.adr(Gpr::x(1), current)?;
        self.code
            .emit(|e| crate::arm::beam_asm::load_x_reg_array(e, Gpr::x(2)))?;
        self.fragment_call(addr(crate::arm::rt::beam_jit_load_nif as *const ()))?;
        emit_leave_runtime(&mut self.code, 2, update)?;

        let schedule = self.code.new_label();
        let next = self.code.new_label();
        self.code.emit(|e| e.cmp_imm(Gpr::x(0), 2, false))?;
        self.code.b_cond(Cond::Eq, schedule)?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(0), 0, false))?;
        self.code.b_cond(Cond::Eq, next)?;
        self.emit_raise_exception(current, &LOAD_NIF_MFA)?;

        self.code.bind(schedule)?;
        self.code.adr(Gpr::x(2), entry)?;
        self.fragment_branch(self.yield_fragments.context_switch)?;
        self.code.bind(next)?;
        Ok(())
    }

    /// Passes a BEAM instruction PC and MFA to the shared exception fragment.
    // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:256-268
    // (emit_raise_exception(Label, const ErtsCodeMFA *)), OTP-29.1.1.
    fn emit_raise_exception(
        &mut self,
        instruction: arinsal_a64::buf::Label,
        mfa: &'static ErtsCodeMfa,
    ) -> Result<(), ModuleError> {
        self.code.adr(Gpr::x(1), instruction)?;
        self.code
            .emit(|e| e.mov_const(Gpr::x(3), mfa as *const ErtsCodeMfa as u64))?;
        self.fragment_branch(self.raise_fragments.1)
    }

    /// Emits an external call through the current address in an export entry.
    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:150-155, OTP-29.1.1
    pub fn emit_i_call_ext(&mut self, export: &'static ExportEntry) -> Result<(), ModuleError> {
        self.emit_export_call(export, false)
    }

    /// Emits an external tail call through the current export-entry address.
    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:157-164, OTP-29.1.1
    pub fn emit_i_call_ext_only(
        &mut self,
        export: &'static ExportEntry,
    ) -> Result<(), ModuleError> {
        self.emit_export_call(export, true)
    }

    /// Deallocates a Y frame and tail-calls an external export.
    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:166-170, OTP-29.1.1
    pub fn emit_i_call_ext_last(
        &mut self,
        export: &'static ExportEntry,
        deallocate: u32,
    ) -> Result<(), ModuleError> {
        self.deallocate(deallocate)?;
        self.emit_i_call_ext_only(export)
    }

    /// Emits `i_bif1/2/3` and `nofail_bif1/2`: `bif` is `bif_table[].f` of a guard BIF.
    ///
    /// With a nonzero `fail` label a failure branches there (`i_bif_guard_shared`), otherwise
    /// `i_bif_body_shared` raises with the MFA `ubif2mfa` finds for `bif`.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:103-170 (emit_i_bif1/2/3, emit_i_bif),
    // OTP-29.1.1: the operands are stored in X0..X2 of the register array, which holds no live
    // value (X0..X3 live in callee-saved machine registers).
    pub fn emit_i_bif(
        &mut self,
        bif: usize,
        args: &[ArgVal],
        fail: u32,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        if args.len() > 3 {
            return Err(ModuleError::InvalidOperand("BIF arity exceeds three"));
        }
        let fragments = self.bif_fragments;
        if fragments.i_bif_body == 0 || fragments.i_bif_guard == 0 {
            return Err(ModuleError::InvalidOperand(
                "i_bif without the i_bif_*_shared fragments",
            ));
        }
        for (i, arg) in args.iter().copied().enumerate() {
            let source = self.source_reg(arg)?;
            self.code
                .emit(|e| e.str_uoff(source, Gpr::x(19), crate::arm::beam_asm::x_ref(i as u32)))?;
        }
        // ARG4 = the BIF function pointer.
        self.code.emit(|e| e.mov_const(Gpr::x(3), bif as u64))?;
        if fail != 0 {
            self.fragment_call(fragments.i_bif_guard)?;
            let label = self.label(fail);
            self.code.cbz(Gpr::x(0), label)?;
        } else {
            self.fragment_call(fragments.i_bif_body)?;
        }
        self.store_operand(dst, Gpr::x(0))
    }

    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:150-170, OTP-29.1.1
    fn emit_export_call(
        &mut self,
        export: &'static ExportEntry,
        tail: bool,
    ) -> Result<(), ModuleError> {
        let target = Gpr::x(14);
        self.code.emit(|e| {
            e.mov_const(Gpr::x(0), export as *const ExportEntry as u64)?;
            e.ldr_regoff(target, Gpr::x(0), ACTIVE_CODE_IX, 3)?;
            if tail {
                e.ldr_post(Gpr::x(30), E, 8)?;
                e.br(target)
            } else {
                e.blr(target)
            }
        })?;
        Ok(())
    }
}
