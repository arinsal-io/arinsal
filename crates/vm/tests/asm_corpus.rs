use arinsal_beam::BeamFile;
use arinsal_beamasm::{ProcessHeader, SchedulerRegisters};
use arinsal_beamjit::{FallbackReason, ModuleEnv, compile_module_with_env};
use arinsal_term::{FunEntry, Term, TermBuilder, VecHeap, from_owned, global_atoms};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

struct CorpusEnv {
    literal_heap: RefCell<VecHeap>,
    lambda_entries: HashMap<u32, Arc<FunEntry>>,
    plain_bifs: std::collections::HashSet<u32>,
}

extern "C" fn build_stacktrace_for_compile(
    _header: *mut arinsal_beamasm::ProcessHeader,
    _trace: u64,
) -> u64 {
    0
}

impl CorpusEnv {
    fn new(module: &arinsal_loader::Module) -> Self {
        Self {
            plain_bifs: module
                .imports
                .iter()
                .enumerate()
                .filter(|(_, import)| import.bif_fn().is_some())
                .map(|(index, _)| index as u32)
                .collect(),
            literal_heap: RefCell::new(VecHeap::new()),
            lambda_entries: module
                .funs
                .iter()
                .map(|slot| (slot.entry.old_index, Arc::clone(&slot.entry)))
                .collect(),
        }
    }
}

extern "C" fn eq(_: u64, _: u64) -> i32 {
    0
}

impl ModuleEnv for CorpusEnv {
    fn integer_literal(&self, _value: i64) -> Result<u64, String> {
        Ok(Term::NIL.tagged_word())
    }

    fn match_string(&self, _bytes: &[u8]) -> Result<u64, String> {
        Ok(0)
    }

    fn bigint_literal(&self, _decimal: &str) -> Result<u64, String> {
        Ok(Term::NIL.tagged_word())
    }

    fn tuple_literal(&self, elements: &[u64]) -> Result<u64, String> {
        // Compilation only needs a tuple of the right arity; the words are opaque here.
        let terms = vec![Term::NIL; elements.len()];
        let mut heap = self.literal_heap.borrow_mut();
        TermBuilder::new(&mut *heap)
            .tuple(&terms)
            .map(Term::tagged_word)
            .map_err(|error| format!("tuple literal: {error:?}"))
    }

    fn sort_map_keys(&self, keys: &[u64]) -> Result<Vec<usize>, String> {
        Ok((0..keys.len()).collect())
    }

    fn atom(&self, beam: &BeamFile, index: u32) -> Result<u64, String> {
        let name = beam
            .atom(index)
            .ok_or_else(|| format!("atom index {index} is out of range"))?;
        let atom = global_atoms()
            .intern(name)
            .map_err(|error| format!("atom {name}: {error:?}"))?;
        Ok(Term::atom(atom).tagged_word())
    }

    fn literal(&self, beam: &BeamFile, index: u32) -> Result<u64, String> {
        let mut heap = self.literal_heap.borrow_mut();
        if let Some(lambda_index) = u32::MAX.checked_sub(index)
            && let Some(entry) = self.lambda_entries.get(&lambda_index)
        {
            return TermBuilder::new(&mut *heap)
                .local_fun(entry, &[])
                .map(Term::tagged_word)
                .map_err(|error| format!("zero-capture fun {lambda_index}: {error:?}"));
        }
        let value = beam.literal(index).map_err(|error| error.to_string())?;
        from_owned(&value, &mut *heap)
            .map(Term::tagged_word)
            .map_err(|error| format!("literal {index}: {error:?}"))
    }

    fn import(&self, beam: &BeamFile, index: u32) -> Result<u32, String> {
        beam.imports
            .get(index as usize)
            .map(|_| index)
            .ok_or_else(|| format!("import index {index} is out of range"))
    }

    fn plain_bif_identity(&self, _beam: &BeamFile, index: u32) -> Option<usize> {
        self.plain_bifs
            .contains(&index)
            .then_some(index as usize + 1)
    }

    fn export_entry(&self, _beam: &BeamFile, index: u32) -> Result<usize, String> {
        Ok(index as usize + 1)
    }

    fn lambda_fun_entry(&self, beam: &BeamFile, index: u32) -> Result<(usize, u8), String> {
        let _ = beam;
        self.lambda_entries
            .get(&index)
            .map(|entry| (Arc::as_ptr(entry) as usize, entry.arity))
            .ok_or_else(|| format!("lambda {index} is missing"))
    }

    fn raise_class_helper(&self) -> usize {
        1
    }

    fn this_node_sysname(&self) -> usize {
        1
    }

    fn sys_perf_counter(&self) -> usize {
        1
    }

    fn apply_runtime(&self) -> arinsal_beamasm::misc::ApplyRuntime {
        extern "C" fn apply(_: *mut ProcessHeader, _: u32) -> usize {
            0
        }
        extern "C" fn apply3(_: *mut ProcessHeader) -> usize {
            0
        }
        extern "C" fn fun(_: *mut ProcessHeader, _: u64, _: u32) -> usize {
            0
        }
        arinsal_beamasm::misc::ApplyRuntime {
            resolver: apply,
            apply3_resolver: apply3,
            apply_fun_shared: 1,
            fun_resolver: fun,
            apply2_fragment: 1,
            apply3_fragment: 1,
        }
    }

    fn build_stacktrace_helper(&self) -> Option<arinsal_beamasm::catch::BuildStacktraceHook> {
        Some(build_stacktrace_for_compile)
    }

    fn export_trampoline(&self) -> usize {
        1
    }
    fn light_bif_fragment(&self) -> usize {
        1
    }

    fn arithmetic_helper(&self) -> arinsal_beamasm::arith::ArithHelper {
        arith
    }
    fn guard_helper(&self) -> arinsal_beamasm::guard::GuardHelper {
        guard
    }
    fn compare_shared(&self) -> arinsal_beamasm::guard::CompareShared {
        arinsal_beamasm::guard::CompareShared {
            eq: (eq as extern "C" fn(u64, u64) -> i32) as usize,
            ..Default::default()
        }
    }
    fn guard_helper3(&self) -> arinsal_beamasm::guard::GuardHelper3 {
        guard3
    }
    fn gc_hook(&self) -> arinsal_beamasm::construct::GcHook {
        gc
    }
    fn map_lookup_helper(&self) -> arinsal_beamjit::MapLookupHelper {
        map_lookup
    }
    fn bif_mfa_helper(&self) -> arinsal_beamjit::BifMfaHelper {
        bif_mfa
    }
    fn bs_match_helper(&self) -> arinsal_beamasm::bs_match::BsMatchHelper {
        bs_match
    }

    fn map_runtime(&self) -> arinsal_beamasm::map::MapRuntime {
        arinsal_beamasm::map::MapRuntime {
            get: map_get,
            get_elements: map_many,
            lookup_module: 0,
            new_map: map_many,
            update_assoc: map_many,
            update_exact: map_many,
            put_single: map_many,
            update_single_assoc_shared: map_fragments(map_get, map_many)
                .update_single_assoc_shared(),
            update_assoc_shared: map_fragments(map_get, map_many).update_assoc_shared(),
            update_exact_shared: map_fragments(map_get, map_many).update_exact_shared(),
            update_single_exact_shared: map_fragments(map_get, map_many)
                .update_single_exact_shared(),
            get_element_shared: map_fragments(map_get, map_many).get_element_shared(),
            get_element_hash_shared: map_fragments(map_get, map_many).get_element_hash_shared(),
        }
    }

    fn bs_create_bin_helper(&self) -> arinsal_beamasm::bs_construct::BsCreateBinHelper {
        bs_create_bin
    }

    fn binary_literal(&self, bytes: &[u8]) -> Result<u64, String> {
        let mut heap = self.literal_heap.borrow_mut();
        TermBuilder::new(&mut *heap)
            .bitstring(bytes, bytes.len() * 8)
            .map(Term::tagged_word)
            .map_err(|error| format!("binary literal: {error:?}"))
    }

    fn exception_resolver(&self) -> arinsal_beamasm::catch::ExceptionResolver {
        exception
    }
    fn fun_resolver(&self) -> arinsal_beamasm::fun::FunResolver {
        fun
    }
}

extern "C" fn arith(_: *mut ProcessHeader, _: u32, _: u64, _: u64, _: u64) -> u64 {
    0
}
extern "C" fn guard(_: *mut ProcessHeader, _: u32, _: u64, _: u64) -> u64 {
    0
}
extern "C" fn guard3(_: *mut ProcessHeader, _: u32, _: u64, _: u64, _: u64) -> u64 {
    0
}
extern "C" fn gc(
    _: *mut ProcessHeader,
    _: *mut SchedulerRegisters,
    _: usize,
    _: usize,
    _: i32,
) -> i32 {
    0
}
extern "C" fn map_lookup(
    _: *mut ProcessHeader,
    _: *mut SchedulerRegisters,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> u64 {
    0
}
extern "C" fn bif_mfa(
    _: *mut ProcessHeader,
    _: *mut SchedulerRegisters,
    _: u64,
    _: u64,
    _: u64,
) -> u64 {
    0
}
extern "C" fn bs_match(_: *mut ProcessHeader, _: u32, _: u64, _: u64, _: u64) -> u64 {
    0
}
extern "C" fn map_get(_: *mut ProcessHeader, _: u64, _: u64, _: u64) -> u64 {
    0
}
extern "C" fn map_many(_: *mut ProcessHeader, _: u64, _: u64, _: u64, _: u64) -> u64 {
    0
}
extern "C" fn bs_create_bin(_: *mut ProcessHeader, _: u64, _: u64, _: u64) -> u64 {
    0
}
extern "C" fn exception(_: *mut ProcessHeader, _: *mut SchedulerRegisters, _: *mut u64) -> usize {
    0
}
extern "C" fn fun(_: *mut ProcessHeader, _: u64, _: u32) -> usize {
    0
}

fn collect_beams(root: &Path, output: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_beams(&path, output);
        } else if path
            .extension()
            .is_some_and(|extension| extension == "beam")
        {
            output.push(path);
        }
    }
}

/// Runs `program` and returns its standard output as a path.
fn command_path(program: &str, args: &[&str]) -> Option<PathBuf> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    let text = text.trim();
    (output.status.success() && !text.is_empty()).then(|| PathBuf::from(text))
}

#[test]
fn otp_and_elixir_corpus_compiles_with_beamasm() {
    let roots = [
        std::env::var_os("ARINSAL_OTP_ROOT")
            .map(PathBuf::from)
            .or_else(|| {
                command_path(
                    "erl",
                    &[
                        "-noshell",
                        "-eval",
                        "io:format(\"~s\",[code:root_dir()]),halt().",
                    ],
                )
            })
            .expect("OTP 29.1.1 root: set ARINSAL_OTP_ROOT or put erl on PATH"),
        std::env::var_os("ARINSAL_ELIXIR_ROOT")
            .map(PathBuf::from)
            .or_else(|| {
                // `lib/elixir` -> `lib` -> the Elixir root.
                command_path("elixir", &["-e", "IO.write(:code.lib_dir(:elixir))"])
                    .and_then(|lib| lib.parent()?.parent().map(PathBuf::from))
            })
            .expect("Elixir root: set ARINSAL_ELIXIR_ROOT or put elixir on PATH"),
    ];
    let mut paths = Vec::new();
    for root in &roots {
        collect_beams(root, &mut paths);
    }
    if let Some(module) = std::env::var_os("ARINSAL_BEAMASM_CORPUS_MODULE") {
        let module = module.to_string_lossy();
        paths.retain(|path| path.file_stem().is_some_and(|stem| stem == module.as_ref()));
    }
    assert!(!paths.is_empty(), "OTP and Elixir BEAM corpus is absent");

    let mut issues = Vec::new();
    let mut reason_counts = std::collections::BTreeMap::<String, usize>::new();
    let mut category_counts = std::collections::BTreeMap::<String, usize>::new();
    let mut native_count = 0usize;
    for path in &paths {
        let bytes =
            std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let beam = arinsal_beam::parse(&bytes)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let module = arinsal_loader::load(&beam)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let env = CorpusEnv::new(&module);
        match compile_module_with_env(&bytes, &env) {
            Ok(compiled) => {
                native_count += compiled.functions.len();
                for function in compiled.unported {
                    let category = match &function.reason {
                        FallbackReason::UnsupportedInstructions => "unsupported instruction",
                        FallbackReason::EmitterError { .. } => "emitter error",
                        FallbackReason::MissingNativeTarget { .. } => "missing native call target",
                        FallbackReason::MissingEntry => "missing native entry",
                        FallbackReason::RuntimeBridge => "runtime bridge",
                        FallbackReason::Excluded => "explicit exclusion",
                    };
                    *category_counts.entry(category.to_owned()).or_default() += 1;
                    match &function.reason {
                        FallbackReason::EmitterError {
                            instruction,
                            details,
                        } => {
                            *reason_counts
                                .entry(format!("emitter {instruction}: {details}"))
                                .or_default() += 1;
                        }
                        FallbackReason::MissingNativeTarget { instruction, .. } => {
                            *reason_counts
                                .entry(format!("call target unavailable via {instruction}"))
                                .or_default() += 1;
                        }
                        FallbackReason::UnsupportedInstructions => {
                            for reason in &function.missing_ops {
                                *reason_counts
                                    .entry(format!("unsupported {reason}"))
                                    .or_default() += 1;
                            }
                        }
                        FallbackReason::MissingEntry
                        | FallbackReason::RuntimeBridge
                        | FallbackReason::Excluded => {
                            for reason in &function.missing_ops {
                                *reason_counts.entry(reason.clone()).or_default() += 1;
                            }
                        }
                    }
                    issues.push(format!(
                        "{}:{}/{}: {:?} ({})",
                        beam.module,
                        function.name,
                        function.arity,
                        function.reason,
                        function.missing_ops.join(",")
                    ));
                }
            }
            Err(error) => {
                *reason_counts
                    .entry(format!("compile error: {error}"))
                    .or_default() += 1;
                issues.push(format!("{}: emitter/compile error: {error}", beam.module));
            }
        }
    }
    issues.sort();
    eprintln!(
        "BeamAsm corpus: {} modules, {native_count} native functions, {} issues",
        paths.len(),
        issues.len()
    );
    for (category, count) in category_counts {
        eprintln!("  fallback {count}: {category}");
    }
    let mut reason_counts = reason_counts.into_iter().collect::<Vec<_>>();
    reason_counts.sort_by(|(left_reason, left_count), (right_reason, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_reason.cmp(right_reason))
    });
    for (reason, count) in reason_counts.iter().take(60) {
        eprintln!("  blocker {count}: {reason}");
    }
    for issue in &issues {
        eprintln!("  {issue}");
    }
    assert!(
        issues.is_empty(),
        "BeamAsm corpus has {} unsupported functions or compile failures",
        issues.len()
    );
}

/// erts BeamAsm reaches every X register through getXRef (beam_asm.hpp:252-259, OTP-29.1.1),
/// so operands above the register cache never send a function to the interpreter. The
/// fixtures keep X6+ operands in most op families; `jit_xmem.rs` runs them against `erl`.
#[test]
fn extended_x_fixtures_compile_with_beamasm() {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("asm_corpus_xmem");
    std::fs::create_dir_all(&root).unwrap();
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../beamjit/tests/fixtures");
    for (file, module) in [
        ("jit_xmem.erl", "jit_xmem"),
        ("jit_xmem_asm.S", "jit_xmem_asm"),
        ("jit_big_range.erl", "jit_big_range"),
    ] {
        let output = std::process::Command::new("erlc")
            .arg("-o")
            .arg(&root)
            .arg(fixtures.join(file))
            .output()
            .expect("erlc must be on PATH");
        assert!(
            output.status.success(),
            "erlc {file}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = std::fs::read(root.join(format!("{module}.beam"))).unwrap();
        let beam = arinsal_beam::parse(&bytes).unwrap();
        let loaded = arinsal_loader::load(&beam).unwrap();
        let env = CorpusEnv::new(&loaded);
        let compiled = compile_module_with_env(&bytes, &env).unwrap();
        let unported = compiled
            .unported
            .iter()
            .map(|function| {
                format!(
                    "{}/{}: {:?} ({})",
                    function.name,
                    function.arity,
                    function.reason,
                    function.missing_ops.join(",")
                )
            })
            .collect::<Vec<_>>();
        assert!(
            unported.is_empty(),
            "{file}: interpreter fallbacks {unported:#?}"
        );
        assert!(
            !compiled.functions.is_empty(),
            "{file}: no native functions"
        );
    }
}

fn map_fragments(
    get: arinsal_beamasm::map::MapGetHelper,
    update: arinsal_beamasm::map::MapUpdateHelper,
) -> &'static arinsal_beamasm::map::MapFragments {
    // One set per process, as the runtime keeps one: the emitters ask for it per instruction.
    static FRAGMENTS: std::sync::OnceLock<arinsal_beamasm::map::MapFragments> =
        std::sync::OnceLock::new();
    FRAGMENTS.get_or_init(|| arinsal_beamasm::map::MapFragments::new(get, update).unwrap())
}

/// Per-module BeamAsm compile time over 200 Elixir modules (`--run-ignored all`, release).
#[test]
#[ignore = "benchmark"]
fn beamasm_compile_time_per_module() {
    let dir = std::env::var_os("ARINSAL_BENCH_BEAMS")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            command_path("elixir", &["-e", "IO.write(:code.lib_dir(:elixir))"])
                .expect("elixir on PATH")
                .join("ebin")
        });
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "beam"))
        .collect();
    files.sort();
    files.truncate(200);
    let mut samples = Vec::new();
    let mut total_bytes = 0usize;
    let mut layout_hash = std::collections::hash_map::DefaultHasher::new();
    let repeat: usize = std::env::var("ARINSAL_BENCH_REPEAT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1);
    for path in files.iter().cycle().take(files.len() * repeat) {
        let bytes = std::fs::read(path).unwrap();
        total_bytes += bytes.len();
        let beam = arinsal_beam::parse(&bytes).unwrap();
        let loaded = arinsal_loader::load(&beam).unwrap();
        let env = CorpusEnv::new(&loaded);
        let start = std::time::Instant::now();
        let compiled = compile_module_with_env(&bytes, &env);
        samples.push(start.elapsed().as_secs_f64() * 1000.0);
        // The layout must not change with a faster compiler: hash the entry offsets.
        if let Ok(compiled) = compiled {
            use std::hash::{Hash, Hasher};
            let base = compiled
                .native
                .entries
                .values()
                .map(|ptr| *ptr as usize)
                .min()
                .unwrap_or(0);
            let mut offsets: Vec<_> = compiled
                .native
                .entries
                .iter()
                .map(|(label, ptr)| (*label, *ptr as usize - base))
                .collect();
            offsets.sort();
            offsets.hash(&mut layout_hash);
            compiled.functions.len().hash(&mut layout_hash);
            if std::env::var_os("ARINSAL_BENCH_PRINT").is_some() {
                let mut one = std::collections::hash_map::DefaultHasher::new();
                offsets.hash(&mut one);
                println!(
                    "MOD {} {:x} fns={} unported={}",
                    compiled.name,
                    one.finish(),
                    compiled.functions.len(),
                    compiled.unported.len()
                );
            }
        }
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = samples.len();
    println!("LAYOUT {:x}", std::hash::Hasher::finish(&layout_hash));
    println!(
        "BEAMASM modules={n} bytes={total_bytes} median={:.3} ms p95={:.3} ms mean={:.3} ms total={:.1} ms",
        samples[n / 2],
        samples[n * 95 / 100],
        samples.iter().sum::<f64>() / n as f64,
        samples.iter().sum::<f64>()
    );
}
