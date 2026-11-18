//! Output half of the port of beam_makeops `emulator_output`: the tables of beam_opcodes.c and
//! beam_opcodes.h as Rust.

use crate::makeops::*;
use std::collections::{BTreeMap, HashMap, HashSet};

impl Makeops {
    /// `opc[]`, `gen_opc[]`, the `genop_<name>_<arity>` numbers.
    pub fn emit_tables(&self) -> String {
        let genop_types = format!("{COMPILER_TYPES}{LOADER_TYPES}");
        // Generate code for specific ops: opc[] in `sort keys %specific_op` order.
        let mut gen_to_spec: HashMap<&str, usize> = HashMap::new();
        let mut num_specific: HashMap<&str, usize> = HashMap::new();
        let mut opc = String::new();
        let mut spec_opnum = 0usize;
        for (key, defs) in &self.specific_op {
            gen_to_spec.insert(key, spec_opnum);
            num_specific.insert(key, defs.len());
            // Pick up all instructions and manufacture sort keys; the most specific
            // instructions must appear first (an 'x' operand before 's' or 'd').
            let mut items: BTreeMap<String, &SpecificDef> = BTreeMap::new();
            for def in defs {
                let sign: String = def
                    .args
                    .iter()
                    .flat_map(|a| a.chars())
                    .filter(|c| *c != '?')
                    .collect();
                let mut sort_key: String = sign
                    .chars()
                    .map(|c| if genop_types.contains(c) { '.' } else { c })
                    .collect();
                sort_key.push(':');
                sort_key.push_str(&sign);
                items.insert(sort_key, def);
            }
            for def in items.values() {
                let args: Vec<&str> = def.args.iter().map(|a| a.trim_end_matches('?')).collect();
                // Calculate the bit mask which should be used to match this instruction.
                let mut bits = [0u32; MAX_SPEC_OPERANDS / 2];
                for (i, ty) in args.iter().enumerate().take(MAX_SPEC_OPERANDS) {
                    let letter = ty.chars().next().unwrap();
                    let value =
                        type_bit(letter).unwrap_or_else(|| panic!("no bit for type {letter}"));
                    let shift = MAX_GENOP_TYPES * (i % 2);
                    bits[i / 2] |= (value << shift) as u32;
                }
                // If there is only one specific instruction the mask is a dummy {0,0,0}.
                let mask = if defs.len() > 1 { bits } else { [0, 0, 0] };
                let sign: String = args.concat();
                opc.push_str(&format!(
                    "    OpEntry {{ name: {:?}, mask: [{:#x}, {:#x}, {:#x}], sign: {:?} }}, // {}\n",
                    print_name(&def.name, &def.args),
                    mask[0],
                    mask[1],
                    mask[2],
                    sign,
                    spec_opnum
                ));
                spec_opnum += 1;
            }
        }
        // The transformations decide which generic instructions have a transform: the first
        // instruction of the left-hand side (`chain_instructions`, `$gen_transform{$first}`).
        let mut has_transform: HashSet<String> = HashSet::new();
        for transformation in &self.transformations {
            if let Some(first) = transformation
                .from
                .iter()
                .find(|item| !item.name.starts_with('.'))
            {
                has_transform.insert(format!("{}/{}", first.name, first.arity));
            }
        }
        // Print the generic instruction table.
        let mut generic = String::new();
        for i in 0..self.gen_opname.len() {
            match &self.gen_opname[i] {
                None => generic.push_str(
                    "    GenOpEntry { name: \"\", arity: 0, specific: 0, num_specific: 0, transform: false },\n",
                ),
                Some(name) => {
                    let arity = self.gen_arity[i];
                    let key = format!("{name}/{arity}");
                    let tr = has_transform.contains(&key);
                    let spec = gen_to_spec.get(key.as_str()).map(|v| *v as i32);
                    if spec.is_none()
                        && !self.obsolete[i]
                        && !self.is_transformed.contains(&(name.clone(), arity))
                    {
                        panic!("instruction {key} has no specific instruction");
                    }
                    generic.push_str(&format!(
                        "    GenOpEntry {{ name: {name:?}, arity: {arity}, specific: {}, num_specific: {}, transform: {tr} }}, // {i}\n",
                        spec.unwrap_or(-1),
                        num_specific.get(key.as_str()).copied().unwrap_or(0),
                    ));
                }
            }
        }
        let mut out = String::from(
            "// Generated from the OTP-29.1.1 tables by build.rs (port of beam_makeops emulator_output).\n",
        );
        out.push_str(&format!(
            "pub(crate) const MAX_GENERIC_OPCODE: usize = {};\npub(crate) const NUM_GENERIC_OPS: usize = {};\npub(crate) const NUM_SPECIFIC_OPS: usize = {};\n",
            self.num_file_opcodes - 1,
            self.gen_opname.len(),
            spec_opnum
        ));
        out.push_str("pub(crate) static OPC: [OpEntry; NUM_SPECIFIC_OPS] = [\n");
        out.push_str(&opc);
        out.push_str("];\n\npub(crate) static GEN_OPC: [GenOpEntry; NUM_GENERIC_OPS] = [\n");
        out.push_str(&generic);
        out.push_str("];\n\n");
        // `#define genop_<name>_<arity> <number>`.
        for (i, name) in self.gen_opname.iter().enumerate() {
            if let Some(name) = name {
                out.push_str(&format!(
                    "#[allow(dead_code)]\npub const GENOP_{}_{}: i32 = {i};\n",
                    name.to_uppercase(),
                    self.gen_arity[i]
                ));
            }
        }
        out
    }

    /// The specific instructions in `opc[]` order (`op_<print_name>` numbering): `sort keys
    /// %specific_op`, then within a key the most specific signature first.
    fn opc_order(&self) -> Vec<&SpecificDef> {
        let genop_types = format!("{COMPILER_TYPES}{LOADER_TYPES}");
        let mut order = Vec::new();
        for defs in self.specific_op.values() {
            let mut items: BTreeMap<String, &SpecificDef> = BTreeMap::new();
            for def in defs {
                let sign: String = def
                    .args
                    .iter()
                    .flat_map(|a| a.chars())
                    .filter(|c| *c != '?')
                    .collect();
                let mut sort_key: String = sign
                    .chars()
                    .map(|c| if genop_types.contains(c) { '.' } else { c })
                    .collect();
                sort_key.push(':');
                sort_key.push_str(&sign);
                items.insert(sort_key, def);
            }
            order.extend(items.into_values());
        }
        order
    }

    /// The BeamAsm glue of the `-jit yes` branch: `beamasm_emit.h` (one
    /// `case op_<print_name>: emit_<name>(args[0], ..., [Span of the rest])`) as the macro
    /// `beamasm_emit!(assembler, specific_op, args)`, and `beamasm_protos.h` as
    /// `BEAMASM_PROTOS` (name, fixed argument count, variable argument list), sorted by name.
    // Port of erts/emulator/utils/beam_makeops:781-857 (emulator_output, `$jit eq 'yes'`),
    // OTP-29.1.1.
    pub fn emit_beamasm_glue(&self) -> String {
        let mut cases = String::new();
        for (number, def) in self.opc_order().into_iter().enumerate() {
            let mut call: Vec<String> =
                (0..def.args.len()).map(|i| format!("$args[{i}]")).collect();
            if def.varargs {
                call.push(format!("&$args[{}..]", def.args.len()));
            }
            cases.push_str(&format!(
                "            {number} => $asm.emit_{}({}), // op_{}\n",
                def.name,
                call.join(", "),
                print_name(&def.name, &def.args)
            ));
        }
        let mut protos: BTreeMap<&str, (usize, bool)> = BTreeMap::new();
        for defs in self.specific_op.values() {
            let def = &defs[0];
            protos.insert(&def.name, (def.args.len(), def.varargs));
        }
        let mut out = String::from(
            "// Generated from the OTP-29.1.1 tables by build.rs (port of beam_makeops, -jit yes).\n\n",
        );
        out.push_str("/// `beamasm_emit.h`: calls the emitter of specific instruction `$op` with its operands.\n");
        out.push_str("#[macro_export]\nmacro_rules! beamasm_emit {\n    ($asm:expr, $op:expr, $args:expr) => {\n        match $op {\n");
        out.push_str(&cases);
        out.push_str(
            "            op => panic!(\"no specific instruction {op}\"),\n        }\n    };\n}\n\n",
        );
        out.push_str("/// `beamasm_protos.h`: every `emit_<name>` the generated dispatch calls, with its fixed\n/// argument count and whether a variable argument list follows.\npub static BEAMASM_PROTOS: &[(&str, usize, bool)] = &[\n");
        for (name, (argc, varargs)) in protos {
            out.push_str(&format!("    ({name:?}, {argc}, {varargs}),\n"));
        }
        out.push_str("];\n");
        out
    }
}
