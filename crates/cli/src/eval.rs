//! Small command-line entry point for unmodified BEAM benchmark functions.
use arinsal_term::{Term, global_atoms};
use arinsal_vm::{Vm, VmError};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

pub fn command(args: &[String]) -> Result<(), VmError> {
    let mut dirs = Vec::new();
    let mut at = 0;
    let mut workers = std::thread::available_parallelism()
        .map_or(1, |count| count.get())
        .saturating_sub(2)
        .max(1);
    while let Some(flag) = args.get(at).map(String::as_str) {
        match flag {
            "-pa" => {
                let path = args
                    .get(at + 1)
                    .ok_or_else(|| VmError::Load("-pa needs a directory".into()))?;
                dirs.push(PathBuf::from(path));
                at += 2;
            }
            "--schedulers" | "+S" => {
                workers = args
                    .get(at + 1)
                    .and_then(|value| value.parse::<usize>().ok())
                    .filter(|&value| value > 0)
                    .ok_or_else(|| VmError::Load(format!("{flag} needs a positive count")))?;
                at += 2;
            }
            _ => break,
        }
    }
    let module = args
        .get(at)
        .ok_or_else(|| VmError::Load("eval needs a module and function".into()))?;
    let function = args
        .get(at + 1)
        .ok_or_else(|| VmError::Load("eval needs a function".into()))?;
    let mut values = Vec::new();
    for arg in &args[at + 2..] {
        if let Ok(integer) = arg.parse::<i64>() {
            values.push(
                Term::small(integer)
                    .ok_or_else(|| VmError::Unsupported("large CLI integer".into()))?,
            );
        } else {
            let atom = global_atoms()
                .intern(arg)
                .map_err(|_| VmError::Load(format!("invalid atom: {arg}")))?;
            values.push(Term::atom(atom));
        }
    }
    let mut vm = boot_node(&dirs, workers)?;
    let beam_name = format!("{module}.beam");
    let path = dirs
        .iter()
        .map(|dir| dir.join(&beam_name))
        .find(|path| path.is_file())
        .ok_or_else(|| VmError::Load(format!("module {module} not found")))?;
    vm.load_file(&path)?;
    let start = Instant::now();
    let outcome = vm.eval_scheduled(module, function, &values, workers)?;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    println!("{}", outcome.text);
    println!("{function} {elapsed:.3}ms");
    if std::env::var_os("ARINSAL_STATS").is_some() {
        let stats = &outcome.stats;
        eprintln!(
            "GC={} GC_NS={} HEAP_WORDS={} INSTRUCTIONS={}",
            stats.gc.collections, stats.gc.nanoseconds, stats.heap_words, stats.instructions
        );
        let mut hottest: Vec<_> = stats.opcodes.iter().collect();
        hottest.sort_unstable_by_key(|(_, count)| std::cmp::Reverse(**count));
        for (op, count) in hottest {
            eprintln!("OP {op} {count}");
        }
        let mut generic: Vec<_> = stats.generic_opcodes.iter().collect();
        generic.sort_unstable_by_key(|(_, count)| std::cmp::Reverse(**count));
        for (op, count) in generic {
            eprintln!("GEN {op} {count}");
        }
    }
    Ok(())
}

/// Starts the node as `arinsal -noshell -noinput -pa Dir...` does (erl_init.c erl_start ->
/// erl_first_process_otp, `init:boot/1`) and returns once `init` reports `{started, started}`:
/// the function then runs in a booted node, as `erl -s` would run it after the boot.
fn boot_node(dirs: &[PathBuf], workers: usize) -> Result<Vm, VmError> {
    let mut argv = vec![
        "arinsal".to_owned(),
        "-noshell".to_owned(),
        "-noinput".to_owned(),
    ];
    for dir in dirs {
        argv.push("-pa".to_owned());
        argv.push(dir.display().to_string());
    }
    let env: BTreeMap<String, String> = std::env::vars().collect();
    let launch = arinsal_args::parse(&argv, &env)
        .map_err(|error| VmError::Load(format!("node arguments: {error:?}")))?;
    arinsal_args::configure_emulator_flags(launch.emulator.clone());
    let mut seeded = vec![("PATH".to_owned(), launch.path.clone())];
    seeded.extend(launch.set_env.iter().map(|(k, v)| (k.clone(), v.clone())));
    arinsal_vm::boot::seed_environment(&seeded);
    let mut vm = arinsal_vm::boot::erl_start(
        std::path::Path::new(&launch.root_dir),
        &launch.boot_args,
        &[],
        workers,
        launch.emulator.debugger_support,
        launch.emulator.debugger_line_breakpoints.unwrap_or(true),
        launch.emulator.distribution_buffer_busy_limit,
    )?;
    let init = Term::atom(
        global_atoms()
            .intern("init")
            .map_err(|_| VmError::Load("invalid atom: init".into()))?,
    );
    loop {
        // `init:get_status/0` calls the registered `init`, which `init:boot/1` registers first.
        if vm.eval_scheduled("erlang", "whereis", &[init], 1)?.text != "undefined" {
            let status = vm.eval_scheduled("init", "get_status", &[], 1)?.text;
            if status == "{started,started}" {
                return Ok(vm);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}
