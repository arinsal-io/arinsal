//! The generic and specific instruction tables built from `tab/*.tab` equal the tables of the
//! real erts: `gen_opc[]`, `opc[]` and the table sizes that `beam_makeops` generated for the
//! target's JIT of OTP 29.1.1 (`-wordsize 64 -jit yes` on genop.tab, the shared tables and
//! `beam/jit/<arch>/*.tab`; recorded per architecture in
//! `tests/fixtures/<arch>/erts_opcode_tables.txt` from `beam_opcodes.c` and `beam_opcodes.h`).

#[test]
fn opcode_tables_equal_the_ones_beam_makeops_generates() {
    #[cfg(target_arch = "aarch64")]
    let expected = include_str!("fixtures/arm/erts_opcode_tables.txt");
    #[cfg(target_arch = "x86_64")]
    let expected = include_str!("fixtures/x86/erts_opcode_tables.txt");
    let actual = arinsal_beamops::erts_tables_dump();
    let expected_lines: Vec<&str> = expected.lines().collect();
    let actual_lines: Vec<&str> = actual.lines().collect();
    for (index, (want, got)) in expected_lines.iter().zip(&actual_lines).enumerate() {
        assert_eq!(want, got, "line {} of the table dump", index + 1);
    }
    assert_eq!(expected_lines.len(), actual_lines.len());
}

/// The emitters the generated `beamasm_emit!` dispatch calls equal erts' `beamasm_protos.h` of
/// the target JIT (`beam_makeops -jit yes`; recorded in `tests/fixtures/<arch>/`).
#[test]
fn beamasm_protos_equal_the_ones_beam_makeops_generates() {
    #[cfg(target_arch = "aarch64")]
    let expected = include_str!("fixtures/arm/beamasm_protos.h");
    #[cfg(target_arch = "x86_64")]
    let expected = include_str!("fixtures/x86/beamasm_protos.h");
    let expected: Vec<(String, usize, bool)> = expected
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("void emit_")?;
            let (name, params) = rest.split_once('(')?;
            let params = params.trim_end_matches(");");
            let types: Vec<&str> = params.split(", ").filter(|p| !p.is_empty()).collect();
            let varargs = types.last().is_some_and(|t| t.starts_with("const Span"));
            Some((name.to_owned(), types.len() - usize::from(varargs), varargs))
        })
        .collect();
    let actual: Vec<(String, usize, bool)> = arinsal_beamops::BEAMASM_PROTOS
        .iter()
        .map(|(name, argc, varargs)| ((*name).to_owned(), *argc, *varargs))
        .collect();
    assert_eq!(actual, expected);
}

/// `opc_generics` of both JIT architectures, whichever one this crate was built for, equals the
/// specific-to-generic mapping of the real `gen_opc[]` of that architecture: build scripts
/// that run on the host generate the target's dispatch from it.
#[test]
fn opc_generics_of_both_architectures_equal_beam_makeops() {
    for (jit, fixture) in [
        ("arm", include_str!("fixtures/arm/erts_opcode_tables.txt")),
        ("x86", include_str!("fixtures/x86/erts_opcode_tables.txt")),
    ] {
        let mut expected = Vec::new();
        for line in fixture.lines().filter(|line| line.starts_with("gen ")) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (number, name) = (
                fields[1].parse::<u16>().unwrap(),
                fields[2].trim_matches('"'),
            );
            let (specific, count) = (
                fields[4].parse::<i64>().unwrap(),
                fields[5].parse().unwrap(),
            );
            if specific >= 0 {
                expected.push((specific as usize, count, name, number));
            }
        }
        expected.sort();
        let expected: Vec<(&str, u16)> = expected
            .into_iter()
            .flat_map(|(_, count, name, number)| std::iter::repeat_n((name, number), count))
            .collect();
        assert_eq!(
            arinsal_beamops::opc_generics(jit).unwrap(),
            expected,
            "{jit}"
        );
    }
}
