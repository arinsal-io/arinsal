//! Small command-line entry point for unmodified BEAM benchmark functions.
use arinsal_term::{Term, global_atoms};
use arinsal_vm::{Vm, VmError};
use std::path::PathBuf;
use std::time::Instant;

pub fn command(args: &[String]) -> Result<(), VmError> {
    let mut dirs = Vec::new();
    let mut at = 0;
    let mut workers = std::thread::available_parallelism()
        .map_or(1, |count| count.get())
        .saturating_sub(2)
        .max(1);
    let mut simulation_seed = None;
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
            "--sim" | "+Zsim" => {
                simulation_seed = Some(
                    args.get(at + 1)
                        .and_then(|value| value.parse::<u64>().ok())
                        .ok_or_else(|| VmError::Load(format!("{flag} needs a seed")))?,
                );
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
    let mut vm = Vm::new(dirs);
    let beam_name = format!("{module}.beam");
    let path = vm
        .paths()
        .iter()
        .map(|dir| dir.join(&beam_name))
        .find(|path| path.is_file())
        .ok_or_else(|| VmError::Load(format!("module {module} not found")))?;
    vm.load_file(&path)?;
    let start = Instant::now();
    let outcome = vm.eval_scheduled(module, function, &values, workers, simulation_seed)?;
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
