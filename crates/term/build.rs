use std::{collections::HashMap, env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=atom.names");
    println!("cargo:rerun-if-changed=../../spec/otp-29.1.1/bif.tab");
    let mut code = String::from("/// Predefined OTP 29.1.1 atom indices.\n");
    let mut names = Vec::new();
    let mut indices = HashMap::new();
    let mut declarations = Vec::new();
    for line in include_str!("atom.names").lines() {
        let line = line.trim();
        if !line.starts_with("atom ") {
            continue;
        }
        for decl in line[5..].split_whitespace() {
            let (identifier, value, aliased) = if let Some((lhs, rhs)) = decl.split_once('=') {
                (lhs, rhs.trim_matches('\''), true)
            } else {
                (decl, decl.trim_matches('\''), false)
            };
            let identifier: String = identifier
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() {
                        c.to_ascii_uppercase()
                    } else {
                        '_'
                    }
                })
                .collect();
            let index = *indices.entry(value.to_owned()).or_insert_with(|| {
                let index = names.len();
                names.push(value.to_owned());
                index
            });
            declarations.push((identifier, value.to_owned(), index, aliased));
        }
    }
    // Port of erts/emulator/utils/make_tables:92-102, OTP-29.1.1: erl_atom_table.c
    // continues with the module and function atoms of every BIF in bif.tab order.
    for line in include_str!("../../spec/otp-29.1.1/bif.tab").lines() {
        let mut fields = line.split_whitespace();
        if !matches!(fields.next(), Some("bif" | "ubif" | "hbif")) {
            continue;
        }
        let Some(mfa) = fields.next() else { continue };
        let (module, rest) = mfa.split_once(':').expect("bif.tab entry has a module");
        let (name, _arity) = rest.rsplit_once('/').expect("bif.tab entry has an arity");
        for atom in [module, name] {
            let atom = atom
                .strip_prefix('\'')
                .and_then(|atom| atom.strip_suffix('\''))
                .unwrap_or(atom);
            if !indices.contains_key(atom) {
                indices.insert(atom.to_owned(), names.len());
                names.push(atom.to_owned());
            }
        }
    }
    let mut used: HashMap<String, String> = HashMap::new();
    for aliased in [false, true] {
        for (identifier, value, index, is_alias) in &declarations {
            if *is_alias != aliased {
                continue;
            }
            if used
                .get(identifier)
                .is_some_and(|existing| existing == value)
            {
                continue;
            }
            let mut name = identifier.clone();
            let mut suffix = 2;
            while used.contains_key(&name) {
                name = format!("{identifier}_{suffix}");
                suffix += 1;
            }
            used.insert(name.clone(), value.clone());
            code.push_str(&format!(
                "/// `{value}`.\npub const {name}: super::Atom = super::Atom({index});\n"
            ));
        }
    }
    code.push_str("/// Atom text in the order used by erts.\npub const PREDEFINED: &[&str] = &[\n");
    for name in &names {
        code.push_str(&format!("    {name:?},\n"));
    }
    code.push_str("];\n");
    fs::write(
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("atoms.rs"),
        code,
    )
    .unwrap();
}
