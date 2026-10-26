//! The transformation programs that the build generator compiles from `tab/*.tab` equal the ones
//! `beam_makeops` of OTP 29.1.1 holds after `group_tr` (dumped by a patched copy of the script run
//! with the arm64 JIT arguments; `tests/fixtures/erts_transform_programs.txt`).

#[test]
fn transform_programs_equal_the_ones_beam_makeops_compiles() {
    let expected = include_str!("fixtures/erts_transform_programs.txt");
    let actual = arinsal_beamops::erts_programs_dump();
    let expected_lines: Vec<&str> = expected.lines().collect();
    let actual_lines: Vec<&str> = actual.lines().collect();
    for (index, (want, got)) in expected_lines.iter().zip(&actual_lines).enumerate() {
        assert_eq!(want, got, "line {} of the program dump", index + 1);
    }
    assert_eq!(expected_lines.len(), actual_lines.len());
}
