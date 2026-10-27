use arinsal_beamops::{specific_op_count, specific_op_info};
use std::{collections::BTreeMap, env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=src/lib.rs");
    let source = fs::read_to_string("src/lib.rs").expect("beamjit source");
    let emitters = parse_emitters(&source);
    let emitter_ids = parse_emitter_ids(&source);
    let mut generated =
        String::from("const fn emitter_from_id(id: u8) -> EmitterKind {\n    match id {\n");
    for (emitter, id) in &emitter_ids {
        generated.push_str(&format!("        {id} => EmitterKind::{emitter},\n"));
    }
    generated.push_str("        _ => panic!(\"invalid generated emitter id\"),\n    }\n}\n\n");
    generated.push_str(
        "fn dispatch_specific_op(\n\
            specific: u16,\n\
            assembler: &mut BeamModuleAssembler,\n\
            op: &OpView<'_>,\n\
            beam: &BeamFile,\n\
            env: &impl ModuleEnv,\n\
            function: &str,\n\
            arity: u8,\n\
        ) -> Result<(), EmitError> {\n\
            match specific {\n",
    );

    for specific in 0..specific_op_count() {
        let Some(info) = specific_op_info(specific as u16) else {
            panic!("missing OPC entry {specific}");
        };
        let Some(emitter) = emitters.get(info.generic_name) else {
            continue;
        };
        let Some(emitter_id) = emitter_ids.get(emitter) else {
            panic!("unknown emitter kind {emitter}");
        };
        generated.push_str(&format!(
            "                {specific} => emit_op::<{}, {emitter_id}>(assembler, op, beam, env, function, arity),\n",
            info.generic_op
        ));
    }
    generated.push_str(
        "                _ => Err(EmitError::Operand(format!(\"no emitter for operation {}\", op.name()))),\n\
            }\n\
        }\n",
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    fs::write(out.join("specific_dispatch.rs"), generated).expect("specific dispatch");
}

fn parse_emitter_ids(source: &str) -> BTreeMap<String, u8> {
    let block = source
        .split_once("enum EmitterKind {")
        .and_then(|(_, rest)| rest.split_once('}').map(|(block, _)| block))
        .expect("EmitterKind enum");
    block
        .lines()
        .filter_map(|line| {
            let variant = line.trim().strip_suffix(',')?.trim();
            if variant.is_empty() || variant.starts_with("//") {
                return None;
            }
            Some(variant.to_owned())
        })
        .enumerate()
        .map(|(id, variant)| (variant, u8::try_from(id).expect("EmitterKind count")))
        .collect()
}

fn parse_emitters(source: &str) -> BTreeMap<String, String> {
    let mut emitters = BTreeMap::new();
    for block in source.split("PortedOp {").skip(1) {
        let block = block.split('}').next().unwrap_or(block);
        let Some(name) = field_string(block, "name:") else {
            continue;
        };
        let Some(emitter) = block
            .split_once("emitter: EmitterKind::")
            .and_then(|(_, rest)| rest.split(|ch: char| !ch.is_ascii_alphanumeric()).next())
        else {
            continue;
        };
        let previous = emitters.insert(name.clone(), emitter.to_owned());
        assert!(
            previous.is_none(),
            "multiple emitters registered for generic operation {name}"
        );
    }
    emitters
}

fn field_string(block: &str, field: &str) -> Option<String> {
    let (_, rest) = block.split_once(field)?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('"')?;
    Some(rest.split('"').next()?.to_owned())
}
