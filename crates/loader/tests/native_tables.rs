//! A module without the interpreter form gets the coverage table and the debugger line
//! metadata the module loaded with its instructions has (`native_coverage`,
//! `set_native_debug_lines`), so BeamAsm emits the same counters and line breakpoints.

use arinsal_loader::CoverageMode;

const SOURCE: &str = "-module(native_tables_fixture).
-export([f/1, g/2]).
f(0) -> zero;
f(N) when N > 0 ->
    M = N - 1,
    {N, f(M)}.
g(A, B) ->
    C = A + B,
    case C of
        0 -> none;
        _ -> C * 2
    end.
";

/// Compiles the fixture with `erlc`; `None` when `erlc` is unavailable.
fn compile(options: &[&str]) -> Option<arinsal_beam::BeamFile> {
    let dir = std::env::temp_dir().join(format!(
        "arinsal_native_tables_{}_{}",
        std::process::id(),
        options.join("_").replace('+', "")
    ));
    std::fs::create_dir_all(&dir).ok()?;
    let source = dir.join("native_tables_fixture.erl");
    std::fs::write(&source, SOURCE).ok()?;
    let status = std::process::Command::new("erlc")
        .args(options)
        .arg("-o")
        .arg(&dir)
        .arg(&source)
        .status()
        .ok()?;
    if !status.success() {
        return None;
    }
    let bytes = std::fs::read(dir.join("native_tables_fixture.beam")).ok()?;
    let _ = std::fs::remove_dir_all(&dir);
    Some(arinsal_beam::parse(&bytes).expect("parse fixture"))
}

#[test]
fn native_coverage_tables_match_the_interpreter_form() {
    let Some(file) = compile(&["+line_coverage"]) else {
        eprintln!("erlc unavailable; skipping native coverage table test");
        return;
    };
    for mode in [
        CoverageMode::Function,
        CoverageMode::FunctionCounters,
        CoverageMode::Line,
        CoverageMode::LineCounters,
    ] {
        let expected = arinsal_loader::load_with_instrumentations(&file, mode, false)
            .expect("load with instructions")
            .coverage
            .expect("coverage table");
        let actual = arinsal_loader::native_coverage(&file, mode)
            .expect("native coverage")
            .expect("coverage table");
        assert_eq!(actual.mode, expected.mode, "{mode:?}");
        assert_eq!(actual.len(), expected.len(), "{mode:?}");
        assert_eq!(actual.lines, expected.lines, "{mode:?}");
        assert_eq!(actual.cover_ids, expected.cover_ids, "{mode:?}");
        assert_eq!(actual.locations, expected.locations, "{mode:?}");
        assert_eq!(
            actual.line_probe_mappings, expected.line_probe_mappings,
            "{mode:?}"
        );
        assert_eq!(actual.function_owners, expected.function_owners, "{mode:?}");
    }
    assert!(
        arinsal_loader::native_coverage(&file, CoverageMode::None)
            .expect("native coverage")
            .is_none()
    );
}

#[test]
fn native_debug_lines_match_the_interpreter_form() {
    let Some(file) = compile(&["+beam_debug_info"]) else {
        eprintln!("erlc unavailable; skipping native debugger line test");
        return;
    };
    let expected = arinsal_loader::load_with_instrumentations(&file, CoverageMode::None, true)
        .expect("load with instructions");
    let mut actual = arinsal_loader::load_native(&file).expect("load native");
    arinsal_loader::set_native_debug_lines(&mut actual, &file);
    assert!(expected.line_breakpoints_supported);
    assert_eq!(
        actual.line_breakpoints_supported,
        expected.line_breakpoints_supported
    );
    assert_eq!(actual.debug_line_items, expected.debug_line_items);
    // The interpreter form keys a point by its instruction; the native form by the entry slot
    // of its function (`2 * ordinal + 1`). Both name the same function, line and live count.
    let owner = |ip: usize| {
        expected
            .functions
            .iter()
            .rposition(|(start, _, _)| *start <= ip)
            .expect("point inside a function")
    };
    let expected_points = expected
        .debug_line_points
        .iter()
        .map(|(ip, line, live)| (owner(*ip), *line, *live))
        .collect::<Vec<_>>();
    let actual_points = actual
        .debug_line_points
        .iter()
        .map(|(slot, line, live)| ((slot - 1) / 2, *line, *live))
        .collect::<Vec<_>>();
    assert_eq!(actual_points, expected_points);
}
