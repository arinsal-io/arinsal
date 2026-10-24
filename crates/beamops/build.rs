use std::{collections::BTreeSet, env, fs, path::PathBuf};

#[path = "src/rule_syntax.rs"]
mod rule_syntax;
use rule_syntax::{Restriction, Top};

fn main() {
    generate_matchers();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ops = fs::read_to_string(root.join("tab/ops.tab")).expect("ops.tab");
    let _predicates = fs::read_to_string(root.join("tab/predicates.tab")).expect("predicates.tab");
    let _common_predicates =
        fs::read_to_string(root.join("tab/common_predicates.tab")).expect("common predicates.tab");
    let _generators = fs::read_to_string(root.join("tab/generators.tab")).expect("generators.tab");
    let _common_generators =
        fs::read_to_string(root.join("tab/common_generators.tab")).expect("common generators.tab");
    for path in [
        "ops.tab",
        "predicates.tab",
        "common_predicates.tab",
        "generators.tab",
        "common_generators.tab",
        "genop.tab",
    ] {
        println!(
            "cargo:rerun-if-changed={}",
            root.join("tab").join(path).display()
        );
    }
    let mut names = BTreeSet::new();
    let mut rules = Vec::new();
    for raw in ops.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('%') {
            continue;
        }
        if let Some((lhs, rhs)) = line.split_once("=>") {
            if let Some(rule) = direct_rule(lhs.trim(), rhs.trim()) {
                rules.push(rule);
            }
            continue;
        }
        if line.contains('|') || line.contains('(') {
            continue;
        }
        let Some(first) = line.split_whitespace().next() else {
            continue;
        };
        let name = first.split('/').next().unwrap_or(first);
        if name.chars().next().is_some_and(|c| c.is_ascii_lowercase())
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            names.insert(name.to_owned());
        }
    }
    let mut out = String::from(
        "// Generated from OTP-29.1.1 ops.tab.\n/// A BeamAsm operation declared by OTP 29.1.1.\n#[derive(Clone, Debug, PartialEq, Eq)]\npub enum SpecificOp {\n",
    );
    for name in &names {
        out.push_str(&format!(
            "    /// `{name}` with typed decoded operands.\n    {}(smallvec::SmallVec<[SpecificOperand; 4]>),\n",
            camel(name)
        ));
    }
    out.push_str("    /// An opcode name absent from OTP's declaration set.\n    Unknown {\n        /// Original opcode name.\n        name: String,\n        /// Typed decoded operands.\n        operands: smallvec::SmallVec<[SpecificOperand; 4]>,\n    },\n}\nimpl SpecificOp { fn from_name(name: &str, args: smallvec::SmallVec<[SpecificOperand; 4]>) -> Self { match name {\n");
    for name in &names {
        out.push_str(&format!("{name:?} => Self::{}(args),\n", camel(name)));
    }
    out.push_str("_ => Self::Unknown { name: name.to_owned(), operands: args },\n} } /// Returns the OTP operation name.\npub fn name(&self) -> &str { match self {\n");
    for name in &names {
        out.push_str(&format!("Self::{}(_) => {:?},\n", camel(name), name));
    }
    out.push_str("Self::Unknown { name, .. } => name,\n} } /// Returns the decoded operands.\npub fn operands(&self) -> &[SpecificOperand] { match self {\n");
    for name in &names {
        out.push_str(&format!("Self::{}(args) => args,\n", camel(name)));
    }
    out.push_str("Self::Unknown { operands, .. } => operands,\n} }\n/// The dense identity of the operation: its index in [`SPECIFIC_OP_NAMES`], `u16::MAX` for an unknown one.\npub fn id(&self) -> u16 { match self {\n");
    for (index, name) in names.iter().enumerate() {
        out.push_str(&format!("Self::{}(_) => {index},\n", camel(name)));
    }
    out.push_str("Self::Unknown { .. } => u16::MAX,\n} } }\n/// All operation names declared in OTP's ARM64 ops table.\npub static SPECIFIC_OP_NAMES: &[&str] = &[\n");
    for name in &names {
        out.push_str(&format!("{name:?},\n"));
    }
    out.push_str("];\n/// A generated one-instruction variable-preserving rewrite.\n#[derive(Clone, Debug, PartialEq, Eq)]\npub struct DirectRule {\n/// Generic input opcode.\npub input: &'static str,\n/// Specific output opcode.\npub output: &'static str,\n/// Source operand indexes copied to the output.\npub operands: &'static [usize],\n}\n/// Direct rewrite rules extracted from `ops.tab`.\npub static DIRECT_RULES: &[DirectRule] = &[\n");
    for (input, output, mapping) in rules {
        let map = mapping
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!(
            "DirectRule {{ input: {input:?}, output: {output:?}, operands: &[{map}] }},\n"
        ));
    }
    out.push_str("];\n");
    fs::write(
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("specific_ops.rs"),
        out,
    )
    .unwrap();
}

fn direct_rule(lhs: &str, rhs: &str) -> Option<(String, String, Vec<usize>)> {
    if lhs.contains('|') || lhs.contains('(') || rhs.contains('|') || rhs.contains('(') {
        return None;
    }
    let l: Vec<_> = lhs.split_whitespace().collect();
    let r: Vec<_> = rhs.split_whitespace().collect();
    if l.is_empty() || r.is_empty() || r[0] == "_" {
        return None;
    }
    let mut bindings = Vec::new();
    for (i, token) in l.iter().enumerate().skip(1) {
        if token.contains('=') {
            return None;
        }
        let capture = *token;
        if capture == "_" || capture.starts_with('_') {
            continue;
        }
        if !capture
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_uppercase())
            || !capture
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return None;
        }
        bindings.push((capture.to_owned(), i - 1));
    }
    let mut mapping = Vec::new();
    for token in r.iter().skip(1) {
        let (_, index) = bindings.iter().find(|(name, _)| name == token)?;
        mapping.push(*index);
    }
    Some((l[0].to_owned(), r[0].to_owned(), mapping))
}

fn camel(name: &str) -> String {
    format!(
        "Op{}",
        name.split('_')
            .map(|part| {
                let mut chars = part.chars();
                chars
                    .next()
                    .map(|c| c.to_uppercase().collect::<String>() + chars.as_str())
                    .unwrap_or_default()
            })
            .collect::<String>()
    )
}

/// The match program of every rule of `ops.tab` as straight-line Rust, one function per rule,
/// the way `beam_makeops` prints the cases of `erts_transform_engine`: no program is
/// interpreted at run time. `MATCHERS[i]` belongs to the `i`-th rule of `parse_rules`.
fn generate_matchers() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = fs::read_to_string(root.join("tab/ops.tab")).expect("ops.tab");
    let source: &'static str = Box::leak(source.into_boxed_str());
    let rules = rule_syntax::parse_rules(source);
    let mut out = String::from(
        "// Generated from OTP-29.1.1 ops.tab by build.rs: the match programs of the transform rules.\n",
    );
    let mut table = String::new();
    for (index, rule) in rules.iter().enumerate() {
        let mut restrictions = String::new();
        let mut body = String::new();
        for top in &rule.program {
            match top {
                Top::NextInstr { op, fixed, rest } => body.push_str(&format!(
                    "    if !f.next_instr({op:?}, {fixed}, {rest}) {{\n        return false;\n    }}\n"
                )),
                Top::IsType { mask, exact_x0 } => {
                    let mask = match mask {
                        Some(mask) => format!("Some({mask:#x})"),
                        None => "None".to_owned(),
                    };
                    body.push_str(&format!(
                        "    if !f.is_type({mask}, {exact_x0}) {{\n        return false;\n    }}\n"
                    ));
                }
                Top::IsEq(n) => body.push_str(&format!(
                    "    if !f.is_eq({n}) {{\n        return false;\n    }}\n"
                )),
                Top::IsAtom(atom) => body.push_str(&format!(
                    "    if !f.is_atom(beam, {atom:?}) {{\n        return false;\n    }}\n"
                )),
                Top::Restriction(restriction) => {
                    let name = format!("R{index}_{}", restrictions.matches("static").count());
                    let value = match restriction {
                        Restriction::IsBif => "Restriction::IsBif".to_owned(),
                        Restriction::IsNotBif => "Restriction::IsNotBif".to_owned(),
                        Restriction::Mfa {
                            module,
                            function,
                            arity,
                        } => format!(
                            "Restriction::Mfa {{ module: {module:?}.to_owned(), function: {function:?}.to_owned(), arity: {arity} }}"
                        ),
                        Restriction::Bif {
                            module,
                            function,
                            arity,
                        } => format!(
                            "Restriction::Bif {{ module: {module:?}.to_owned(), function: {function:?}.to_owned(), arity: {arity} }}"
                        ),
                    };
                    restrictions.push_str(&format!(
                        "    static {name}: std::sync::LazyLock<Restriction> = std::sync::LazyLock::new(|| {value});\n"
                    ));
                    body.push_str(&format!(
                        "    if !f.restriction(beam, &{name}) {{\n        return false;\n    }}\n"
                    ));
                }
                Top::SetVar(slot) => body.push_str(&format!(
                    "    if !f.set_var(slots, {slot}) {{\n        return false;\n    }}\n"
                )),
                Top::NextArg => body.push_str("    f.next_arg();\n"),
                Top::RestArgs { slot, fixed } => {
                    let slot = match slot {
                        Some(slot) => format!("Some({slot})"),
                        None => "None".to_owned(),
                    };
                    body.push_str(&format!("    f.rest_args(slots, {slot}, {fixed});\n"));
                }
            }
        }
        out.push_str(&format!(
            "#[allow(unused_variables, unused_mut)]\nfn rule_{index}<'a>(\n    code: &'a [Node],\n    at: usize,\n    beam: Option<&BeamFile>,\n    slots: &mut SlotVec<'a>,\n) -> bool {{\n{restrictions}    let mut f = Frame::new(code, at);\n{body}    true\n}}\n\n"
        ));
        table.push_str(&format!("    rule_{index},\n"));
    }
    out.push_str(&format!(
        "/// The match function of each rule, in the order of `ops.tab`.\nstatic MATCHERS: [MatchFn; {}] = [\n{table}];\n",
        rules.len()
    ));
    fs::write(
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("matchers.rs"),
        out,
    )
    .unwrap();
    println!("cargo:rerun-if-changed=src/rule_syntax.rs");
}
