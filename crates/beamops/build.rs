use std::{collections::BTreeSet, env, fs, path::PathBuf};

fn main() {
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
            "    /// `{name}` with typed decoded operands.\n    {}(Vec<SpecificOperand>),\n",
            camel(name)
        ));
    }
    out.push_str("    /// An opcode name absent from OTP's declaration set.\n    Unknown {\n        /// Original opcode name.\n        name: String,\n        /// Typed decoded operands.\n        operands: Vec<SpecificOperand>,\n    },\n}\nimpl SpecificOp { fn from_name(name: &str, args: Vec<SpecificOperand>) -> Self { match name {\n");
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
    out.push_str("Self::Unknown { operands, .. } => operands,\n} } }\n/// All operation names declared in OTP's ARM64 ops table.\npub static SPECIFIC_OP_NAMES: &[&str] = &[\n");
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
