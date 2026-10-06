use arinsal_difftest::{RefErl, Vm as _, compare, suites};
use std::collections::HashSet;
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut vm = String::from("erl");
    let mut suite = String::from("stage1");
    let mut show_mismatches = 0usize;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--vm" => vm = args.next().ok_or("missing --vm value")?,
            "--suite" => suite = args.next().ok_or("missing --suite value")?,
            "--show-mismatches" => {
                show_mismatches = args
                    .next()
                    .ok_or("missing --show-mismatches value")?
                    .parse()?;
            }
            "--help" | "-h" => {
                println!(
                    "Usage: difftest --vm erl|arinsal --suite stage1|<module> [--show-mismatches N]"
                );
                return Ok(());
            }
            _ => return Err(format!("unknown argument {arg}").into()),
        }
    }
    if vm != "erl" && vm != "arinsal" {
        return Err(format!("unknown VM {vm}; expected erl or arinsal").into());
    }

    let cases = suites::stage1()
        .into_iter()
        .filter(|case| suite == "stage1" || case.spec.module == suite)
        .collect::<Vec<_>>();
    if cases.is_empty() {
        return Err(format!("unknown suite {suite}").into());
    }

    let began = Instant::now();
    let mut functions = HashSet::new();
    let mut failed_functions = HashSet::new();
    let mut mismatches = 0usize;
    let mut shown = 0usize;
    let (erl, erl_second, mut arinsal) = if vm == "erl" {
        (Some(RefErl::start()?), Some(RefErl::start()?), None)
    } else {
        (Some(RefErl::start()?), None, Some(arinsal_vm::Vm::new([])))
    };

    for case in &cases {
        let function = (case.spec.module, case.spec.function);
        functions.insert(function);
        let (left, right) = if let Some(arinsal) = arinsal.as_mut() {
            let left = erl.as_ref().expect("reference VM initialized").call(
                case.spec.module,
                case.spec.function,
                &case.args,
            );
            let right = arinsal.call(case.spec.module, case.spec.function, &case.args);
            (left, right)
        } else {
            let left = erl_second
                .as_ref()
                .expect("second reference VM initialized")
                .call(case.spec.module, case.spec.function, &case.args);
            let right = erl.as_ref().expect("reference VM initialized").call(
                case.spec.module,
                case.spec.function,
                &case.args,
            );
            (left, right)
        };

        if let Err(diff) = compare(&left, &right, case.spec.mode) {
            mismatches += 1;
            failed_functions.insert(function);
            if shown < show_mismatches {
                let (left_name, right_name) = if vm == "arinsal" {
                    ("erl", "arinsal")
                } else {
                    ("erl-1", "erl-2")
                };
                eprintln!(
                    "{} args={:?}\n  {left_name}: {:?}\n  {right_name}: {:?}\n  diff: {diff}",
                    case.name, case.args, left, right
                );
                shown += 1;
            }
        }
    }

    println!("suite       functions  function_pass  cases  passed  mismatches  elapsed");
    println!(
        "{suite:<11} {:>9}  {:>13}  {:>5}  {:>6}  {:>10}  {:.2?}",
        functions.len(),
        functions.len() - failed_functions.len(),
        cases.len(),
        cases.len() - mismatches,
        mismatches,
        began.elapsed()
    );
    if mismatches != 0 {
        std::process::exit(1);
    }
    Ok(())
}
