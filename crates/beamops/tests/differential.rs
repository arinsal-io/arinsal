use arinsal_beam::parse;
use arinsal_beamops::{SPECIFIC_OP_NAMES, SpecificOp, SpecificOperand, transform_module};
use std::{collections::HashMap, fs, process::Command, sync::OnceLock};

#[test]
fn otp29_jit_specific_op_names_and_argument_types() {
    if std::env::var_os("BEAMOPS_DIFF").is_none() {
        return;
    }
    let all_modules = [
        "lists",
        "maps",
        "gen_server",
        "ets",
        "string",
        "binary",
        "unicode",
        "Elixir.Enum",
        "Elixir.Map",
        "Elixir.String",
    ];
    let selected = std::env::var("BEAMOPS_MODULES").ok();
    let modules = all_modules
        .into_iter()
        .filter(|module| {
            selected
                .as_ref()
                .is_none_or(|list| list.split(',').any(|candidate| candidate == *module))
        })
        .collect::<Vec<_>>();
    let dir = std::env::temp_dir().join(format!("arinsal-beamops-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let elixir = "$HOME/.asdf/installs/elixir/1.20.4-otp-29/lib/elixir/ebin";
    let atoms = modules
        .iter()
        .map(|m| format!("'{}'", m))
        .collect::<Vec<_>>()
        .join(",");
    let eval = format!(
        "Ms=[{atoms}], lists:foreach(fun(M) -> code:ensure_loaded(M) end, Ms), lists:foreach(fun(M) -> io:format(\"BEAM|~s|~s~n\", [M, code:which(M)]) end, Ms), halt()."
    );
    let status = Command::new("erl")
        .args(["+JDdump", "true", "-noshell", "-pa", elixir, "-eval", &eval])
        .env("PATH", format!("$HOME/.asdf/installs/erlang/29.1.1/bin:$HOME/.asdf/installs/elixir/1.20.4-otp-29/bin:{}", std::env::var("PATH").unwrap_or_default()))
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let paths = String::from_utf8(status.stdout)
        .unwrap()
        .lines()
        .filter_map(|line| {
            let mut parts = line.split('|');
            if parts.next()? != "BEAM" {
                return None;
            }
            Some((parts.next()?.to_owned(), parts.next()?.to_owned()))
        })
        .collect::<std::collections::HashMap<_, _>>();
    let mut failures = Vec::new();
    for module in modules {
        eprintln!("{module}: load BEAM and rewrite");
        let beam_path = paths.get(module).unwrap();
        let beam = parse(&fs::read(beam_path).unwrap()).unwrap();
        eprintln!(
            "{module}: parsed {} instructions",
            beam.code.instructions.len()
        );
        let ours_ops = transform_module(&beam)
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let dump = fs::read_to_string(dir.join(format!("{module}.asm"))).unwrap();
        let expected_ops = dump
            .lines()
            .filter_map(|line| line.trim().strip_prefix("# "))
            .filter_map(parse_reference_op)
            .collect::<Vec<_>>();
        let ours = ours_ops
            .iter()
            .map(|op| op.name().to_owned())
            .collect::<Vec<_>>();
        let ours_signatures = ours_ops.iter().map(specific_signature).collect::<Vec<_>>();
        let expected = expected_ops
            .iter()
            .map(|op| op.name.clone())
            .collect::<Vec<_>>();
        let expected_signatures = expected_ops
            .iter()
            .map(|op| op.suffix.clone())
            .collect::<Vec<_>>();
        let count = expected.len();
        let matched = lcs_len(&ours, &expected);
        let pairs = lcs_pairs(&ours, &expected);
        let suffix_matched = pairs
            .iter()
            .filter(|(ours_index, expected_index)| {
                ours_signatures[*ours_index] == expected_signatures[*expected_index]
            })
            .count();
        eprintln!(
            "{module}: {matched}/{count} op names matched; argument-type suffix {suffix_matched}/{matched} matched"
        );
        if matched * 200 < count * 199 {
            failures.push(format!("{module}: {matched}/{count}"));
        }
    }
    assert!(
        failures.is_empty(),
        "99.5% specific-op name gate failed: {}",
        failures.join(", ")
    );
}

fn lcs_len(left: &[String], right: &[String]) -> usize {
    let (rows, columns) = if left.len() < right.len() {
        (left, right)
    } else {
        (right, left)
    };
    let mut previous = vec![0_u32; rows.len() + 1];
    let mut current = previous.clone();
    for expected in columns {
        for (index, actual) in rows.iter().enumerate() {
            current[index + 1] = if actual == expected {
                previous[index] + 1
            } else {
                current[index].max(previous[index + 1])
            };
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[rows.len()] as usize
}

#[derive(Debug)]
struct ReferenceOp {
    name: String,
    suffix: String,
}

fn parse_reference_op(text: &str) -> Option<ReferenceOp> {
    let name = SPECIFIC_OP_NAMES
        .iter()
        .filter(|name| text.starts_with(&format!("{name}_")))
        .max_by_key(|name| name.len())?;
    Some(ReferenceOp {
        name: (*name).to_owned(),
        suffix: text
            .strip_prefix(&format!("{name}_"))?
            .split_whitespace()
            .next()?
            .to_owned(),
    })
}

fn declarations() -> &'static HashMap<&'static str, Vec<Vec<&'static str>>> {
    static DECLARATIONS: OnceLock<HashMap<&'static str, Vec<Vec<&'static str>>>> = OnceLock::new();
    DECLARATIONS.get_or_init(|| {
        let mut declarations = HashMap::new();
        for raw in include_str!("../tab/ops.tab").lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() || line.contains("=>") {
                continue;
            }
            let mut words = line.split_whitespace();
            let Some(name) = words.next() else { continue };
            if SPECIFIC_OP_NAMES.contains(&name) {
                let types = words.collect::<Vec<_>>();
                if types.iter().all(|ty| {
                    *ty == "*"
                        || ty
                            .chars()
                            .all(|ch| "rxyancsSdfjLHBWAIFbPQMteqlo".contains(ch))
                }) {
                    declarations
                        .entry(name)
                        .or_insert_with(Vec::new)
                        .push(types);
                }
            }
        }
        declarations
    })
}

fn specific_signature(op: &SpecificOp) -> String {
    let Some(candidates) = declarations().get(op.name()) else {
        return String::new();
    };
    candidates
        .iter()
        .find_map(|types| signature_for(types, op.operands()))
        .unwrap_or_default()
}

fn signature_for(types: &[&str], operands: &[SpecificOperand]) -> Option<String> {
    let variable = types.contains(&"*");
    let fixed = types.iter().filter(|ty| **ty != "*").count();
    if fixed > operands.len() || (!variable && fixed != operands.len()) {
        return None;
    }
    let mut suffix = String::new();
    for (operand_index, ty) in types.iter().enumerate() {
        if *ty == "*" {
            break;
        }
        let selected = if ty.len() == 1 {
            ty.chars().next()?
        } else {
            let operand = &operands[operand_index];
            let actual = operand_type(operand);
            let actual = if matches!(
                operand,
                SpecificOperand::SmallInt(_) | SpecificOperand::Unsigned(_)
            ) && ty.contains('F')
            {
                'F'
            } else if ty.contains('S')
                && !matches!(
                    operand,
                    SpecificOperand::Literal(_) | SpecificOperand::FloatRegister(_)
                )
            {
                'S'
            } else {
                actual
            };
            if ty.contains(actual) {
                actual
            } else {
                return None;
            }
        };
        suffix.push(selected);
    }
    Some(suffix)
}

fn operand_type(operand: &SpecificOperand) -> char {
    match operand {
        SpecificOperand::X(_) => 'x',
        SpecificOperand::Y(_) => 'y',
        SpecificOperand::FloatRegister(_) => 'l',
        SpecificOperand::Label(0) => 'p',
        SpecificOperand::Label(_) => 'f',
        SpecificOperand::Atom(_) => 'a',
        SpecificOperand::Export(_) => 'e',
        SpecificOperand::Literal(_) => 'q',
        SpecificOperand::SmallInt(_) => 'i',
        SpecificOperand::Unsigned(_) => 'u',
        SpecificOperand::Nil => 'n',
        SpecificOperand::List(_) => 'o',
        SpecificOperand::Allocations(_) | SpecificOperand::Other => '?',
    }
}

fn lcs_pairs(left: &[String], right: &[String]) -> Vec<(usize, usize)> {
    fn row(left: &[String], right: &[String]) -> Vec<u32> {
        let mut previous = vec![0_u32; right.len() + 1];
        let mut current = previous.clone();
        for a in left {
            for (index, b) in right.iter().enumerate() {
                current[index + 1] = if a == b {
                    previous[index] + 1
                } else {
                    current[index].max(previous[index + 1])
                };
            }
            std::mem::swap(&mut previous, &mut current);
            current.fill(0);
        }
        previous
    }

    fn recurse(
        left: &[String],
        right: &[String],
        left_offset: usize,
        right_offset: usize,
        pairs: &mut Vec<(usize, usize)>,
    ) {
        if left.is_empty() || right.is_empty() {
            return;
        }
        if left.len() == 1 {
            if let Some(index) = right.iter().position(|item| item == &left[0]) {
                pairs.push((left_offset, right_offset + index));
            }
            return;
        }
        let middle = left.len() / 2;
        let forward = row(&left[..middle], right);
        let reversed_left = left[middle..].iter().rev().cloned().collect::<Vec<_>>();
        let reversed_right = right.iter().rev().cloned().collect::<Vec<_>>();
        let backward = row(&reversed_left, &reversed_right);
        let split = (0..=right.len())
            .max_by_key(|index| forward[*index] + backward[right.len() - *index])
            .unwrap_or(0);
        recurse(
            &left[..middle],
            &right[..split],
            left_offset,
            right_offset,
            pairs,
        );
        recurse(
            &left[middle..],
            &right[split..],
            left_offset + middle,
            right_offset + split,
            pairs,
        );
    }

    let mut pairs = Vec::new();
    recurse(left, right, 0, 0, &mut pairs);
    pairs
}
