//! The generic and specific instruction tables built from `tab/*.tab` equal the tables of the
//! real erts: `gen_opc[]`, `opc[]` and the table sizes that `beam_makeops` generated for the
//! arm64 JIT of OTP 29.1.1 (`-wordsize 64 -jit yes`, run on the same tables; recorded in
//! `tests/fixtures/erts_opcode_tables.txt` from `beam_opcodes.c` and `beam_opcodes.h`).

#[test]
fn opcode_tables_equal_the_ones_beam_makeops_generates() {
    let expected = include_str!("fixtures/erts_opcode_tables.txt");
    let actual = arinsal_beamops::erts_tables_dump();
    let expected_lines: Vec<&str> = expected.lines().collect();
    let actual_lines: Vec<&str> = actual.lines().collect();
    for (index, (want, got)) in expected_lines.iter().zip(&actual_lines).enumerate() {
        assert_eq!(want, got, "line {} of the table dump", index + 1);
    }
    assert_eq!(expected_lines.len(), actual_lines.len());
}
