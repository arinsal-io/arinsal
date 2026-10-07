use std::{collections::HashMap, env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=atom.names");
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
