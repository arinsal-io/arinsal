//! Port of the table-building half of erts/emulator/utils/beam_makeops (OTP-29.1.1): the parse of
//! genop.tab, predicates.tab, generators.tab and ops.tab, the numbering of generic instructions,
//! the specific instructions, and the transformations as the engine generator sees them.
//!
//! The Perl subs ported here are: the main input loop, `parse_specific_op`, `parse_c_args`,
//! `parse_transformation`, `compile_transform_function`, `compile_transform`, `tr_parse_op`,
//! `print_name`, and the numbering that `emulator_output` and the code after the loop perform.

// The fields of the parsed transformations are read by the engine generator.
#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap, HashSet};

/// `$max_genop_types`.
pub const MAX_GENOP_TYPES: usize = 16;
/// `$max_spec_operands`.
pub const MAX_SPEC_OPERANDS: usize = 6;
/// `$compiler_types`.
pub const COMPILER_TYPES: &str = "uiaxyfhz";
/// `$loader_types`.
pub const LOADER_TYPES: &str = "nprvlqo";
/// `$pattern_types`.
const PATTERN_TYPES: &str = "acdfjilnopqsuxy";

/// `%arg_size`: the types a specific instruction may use.
const ARG_SIZE_TYPES: &str = "rxyancsSdfjeLtIWbFAPQhlqMH";

/// `%type_bit` for every type letter.
pub fn type_bit(letter: char) -> Option<u64> {
    let genop_types: Vec<char> = format!("{COMPILER_TYPES}{LOADER_TYPES}").chars().collect();
    let primitive = |c: char| genop_types.iter().position(|t| *t == c).map(|i| 1u64 << i);
    match letter {
        'd' => Some(primitive('x')? | primitive('y')?),
        'c' => Some(primitive('i')? | primitive('a')? | primitive('n')? | primitive('q')?),
        's' => Some(
            type_bit('d')? | primitive('i')? | primitive('a')? | primitive('n')? | primitive('q')?,
        ),
        'S' => type_bit('d'),
        'j' => Some(primitive('f')? | primitive('p')?),
        't' | 'I' | 'W' | 'A' | 'L' | 'b' | 'F' | 'e' | 'Q' | 'P' | 'M' | 'H' => primitive('u'),
        other => primitive(other),
    }
}

/// One operand of a transformation pattern or construction: `[var, type, type_val, cond,
/// cond_val]` of `tr_parse_op`.
#[derive(Clone, Debug)]
pub struct TrOp {
    pub var: String,
    pub ty: String,
    pub type_val: String,
    pub cond: String,
    pub cond_val: String,
}

/// An instruction of a transformation, or a call of a predicate or generator (a name that starts
/// with a period, `compile_transform_function`).
#[derive(Clone, Debug)]
pub struct TrItem {
    pub name: String,
    pub arity: usize,
    pub ops: Vec<TrOp>,
    /// The arguments of a call (variable names or numbers).
    pub call_args: Vec<String>,
}

/// An element of `@transformations`.
#[derive(Clone, Debug)]
pub struct Transformation {
    pub loc: String,
    pub orig: String,
    pub from: Vec<TrItem>,
    /// The right-hand side in reverse order, as `parse_transformation` stores it.
    pub to: Vec<TrItem>,
}

/// An entry of `%specific_op`.
#[derive(Clone, Debug)]
pub struct SpecificDef {
    pub name: String,
    pub varargs: bool,
    pub args: Vec<String>,
}

/// A C code block (`pred.name(...) {...}` or `gen.name(...) {...}`).
#[derive(Clone, Debug)]
pub struct CBlock {
    pub body: String,
    pub loc: String,
    pub params: Vec<String>,
}

/// Everything `beam_makeops` knows after the input loop and the numbering.
#[derive(Default)]
pub struct Makeops {
    pub gen_opname: Vec<Option<String>>,
    pub gen_arity: Vec<usize>,
    pub obsolete: Vec<bool>,
    pub gen_opnum: HashMap<(String, usize), usize>,
    /// `%specific_op`: key `name/arity`, sorted like Perl's `sort keys`.
    pub specific_op: BTreeMap<String, Vec<SpecificDef>>,
    pub is_transformed: HashSet<(String, usize)>,
    pub transformations: Vec<Transformation>,
    pub c_code: BTreeMap<String, CBlock>,
    pub num_file_opcodes: usize,
    pub beam_format_number: Option<String>,
    unnumbered_generic: Vec<(String, usize)>,
    unnumbered: HashSet<(String, usize)>,
    gen_arity_by_name: HashMap<String, usize>,
    specific_op_arity: HashMap<String, (usize, String)>,
    print_name: HashMap<String, String>,
    intentionally_unused: HashSet<String>,
}

fn error(message: &str) -> ! {
    panic!("beam_makeops port: {message}");
}

/// `print_name`.
pub fn print_name(name: &str, args: &[String]) -> String {
    let sign: String = args
        .iter()
        .flat_map(|a| a.chars())
        .filter(|c| *c != '?')
        .collect();
    if sign.is_empty() {
        name.to_owned()
    } else {
        format!("{name}_{sign}")
    }
}

impl Makeops {
    /// The main input loop of beam_makeops over `files` in order (`<>` reads them as one stream
    /// whose `$ARGV` and `$.` restart per file), with the `-D` definitions of the build.
    pub fn parse(files: &[(&str, &str)], defs: &HashMap<String, i64>) -> Self {
        let mut me = Makeops::default();
        for (file, text) in files {
            me.parse_file(file, text, defs);
        }
        me.number_generic_ops();
        me.verify_specific_ops();
        me
    }

    fn parse_file(&mut self, file: &str, text: &str, defs: &HashMap<String, i64>) {
        let lines: Vec<&str> = text.lines().collect();
        let mut index = 0;
        let mut if_val: Vec<bool> = Vec::new();
        let mut if_line: Vec<usize> = Vec::new();
        let mut in_c_code: Option<String> = None;
        let mut c_code_block = String::new();
        let mut c_code_loc = String::new();
        let mut c_args: Vec<String> = Vec::new();
        while index < lines.len() {
            let mut line = lines[index].to_owned();
            let lineno = index + 1;
            index += 1;
            if let Some(name) = in_c_code.clone() {
                if line.starts_with('}') {
                    let body = c_code_block
                        .lines()
                        .map(|l| l.strip_prefix("    ").unwrap_or(l))
                        .collect::<Vec<_>>()
                        .join("\n");
                    self.c_code.insert(
                        name,
                        CBlock {
                            body,
                            loc: c_code_loc.clone(),
                            params: c_args.clone(),
                        },
                    );
                    in_c_code = None;
                } else {
                    c_code_block.push_str(&line);
                    c_code_block.push('\n');
                }
                continue;
            }
            if line.ends_with('\\') {
                error("line continuation with `\\` is no longer allowed");
            }
            // Automatically continue a line that ends in '|' or '=>'.
            while (line.ends_with('|') || line.ends_with("=>")) && index < lines.len() {
                let next = lines[index];
                index += 1;
                line.push(' ');
                line.push_str(next);
                if next.is_empty() {
                    break;
                }
            }
            let loc = format!("{file}({lineno})");
            let trimmed = line.trim();
            if trimmed.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            // Handle %if.
            if let Some(rest) = line.strip_prefix("%if ") {
                let name = word(rest);
                let val = *defs
                    .get(name)
                    .unwrap_or_else(|| error(&format!("'{name}' is undefined")));
                if_val.push(val != 0);
                if_line.push(lineno);
                continue;
            } else if let Some(rest) = line.strip_prefix("%unless ") {
                let name = word(rest);
                let val = *defs
                    .get(name)
                    .unwrap_or_else(|| error(&format!("'{name}' is undefined")));
                if_val.push(val == 0);
                if_line.push(lineno);
                continue;
            } else if line == "%else" {
                let last = if_val
                    .len()
                    .checked_sub(1)
                    .unwrap_or_else(|| error("%else without a preceding %if/%unless"));
                if_line[last] = lineno;
                if_val[last] = !if_val[last];
                continue;
            } else if line == "%endif" {
                if if_val.pop().is_none() {
                    error("%endif without a preceding %if/%unless/%else");
                }
                if_line.pop();
                continue;
            }
            if if_val.last() == Some(&false) {
                continue;
            }
            // Handle assignments: /^([\w_][\w\d_]+)=(.*)/
            if let Some((name, value)) = assignment(&line) {
                let value = value.trim_end().trim_end_matches(';').trim_end();
                if name == "BEAM_FORMAT_NUMBER" {
                    self.beam_format_number = Some(value.to_owned());
                }
                // FORBIDDEN_TYPES and the other assignments do not influence the tables.
                continue;
            }
            // Handle %hot, %warm, and %cold.
            if line.starts_with("%hot") || line.starts_with("%warm") || line.starts_with("%cold") {
                continue;
            }
            // Handle %unused.
            if let Some(rest) = line.strip_prefix("%unused")
                && rest.starts_with(char::is_whitespace)
            {
                self.intentionally_unused
                    .insert(word(rest.trim_start()).to_owned());
                continue;
            }
            if line.starts_with('%') {
                error(&format!(
                    "Unrecognized directive '{}'",
                    &line[..line.find(char::is_whitespace).unwrap_or(line.len())]
                ));
            }
            // Handle transformations.
            if line.contains("=>") {
                self.parse_transformation(&loc, &line);
                continue;
            }
            // Handle C code blocks: /^(\w[\w.]*)\(([^\)]*)\)\s*{/
            if let Some((name, args)) = c_block_start(&line) {
                if let Some(previous) = self.c_code.get(&name) {
                    error(&format!("{name}: already defined at {}", previous.loc));
                }
                in_c_code = Some(name);
                c_code_block.clear();
                c_args = parse_c_args(&args);
                c_code_loc = loc.clone();
                continue;
            }
            // Handle definition of instructions in terms of micro instructions (`:=`): only
            // present in the emulator tables.
            if combined_instruction(&line) {
                continue;
            }
            // Parse off the number of the operation.
            let mut op_num: Option<usize> = None;
            let mut rest = line.as_str();
            if let Some(colon) = rest.find(':')
                && colon > 0
                && rest[..colon].bytes().all(|b| b.is_ascii_digit())
            {
                let number: usize = rest[..colon].parse().unwrap();
                if number == 0 {
                    error("Opcode 0 invalid");
                }
                if self.gen_opname.get(number).is_some_and(Option::is_some) {
                    error(&format!("Opcode {number} already defined"));
                }
                op_num = Some(number);
                rest = rest[colon + 1..].trim_start();
            }
            // Parse: Name/Arity (generic instruction): m@^(-)?(\w+)/(\d)\s*$@
            if let Some((obsolete, name, arity)) = generic_op(rest) {
                if !name.starts_with(|c: char| c.is_ascii_lowercase()) {
                    error("Opname must start with a lowercase letter");
                }
                if self
                    .gen_arity_by_name
                    .get(name)
                    .is_some_and(|a| *a != arity)
                {
                    error(&format!(
                        "Opname {name} already defined with arity {}",
                        self.gen_arity_by_name[name]
                    ));
                }
                if self.unnumbered.contains(&(name.to_owned(), arity)) {
                    error(&format!("Opname {name} already defined"));
                }
                if let Some(op_num) = op_num {
                    if self.gen_opname.len() <= op_num {
                        self.gen_opname.resize(op_num + 1, None);
                        self.gen_arity.resize(op_num + 1, 0);
                        self.obsolete.resize(op_num + 1, false);
                    }
                    self.gen_opname[op_num] = Some(name.to_owned());
                    self.gen_arity[op_num] = arity;
                    self.gen_opnum.insert((name.to_owned(), arity), op_num);
                    self.gen_arity_by_name.insert(name.to_owned(), arity);
                    self.obsolete[op_num] = obsolete;
                } else {
                    self.unnumbered_generic.push((name.to_owned(), arity));
                    self.unnumbered.insert((name.to_owned(), arity));
                }
                continue;
            }
            // Parse specific instructions: Name Arg1 Arg2...
            let (name, arity) = self.parse_specific_op(&loc, rest);
            if op_num.is_some() {
                error("specific instructions must not be numbered");
            } else if !self.gen_arity_by_name.contains_key(&name)
                && !self.unnumbered.contains(&(name.clone(), arity))
            {
                // Create an unnumbered generic instruction too.
                self.unnumbered_generic.push((name.clone(), arity));
                self.unnumbered.insert((name, arity));
            }
        }
        if let Some(open) = if_line.last() {
            error(&format!("Unterminated %if/%unless/%else at line {open}"));
        }
    }

    /// `parse_specific_op`.
    fn parse_specific_op(&mut self, loc: &str, text: &str) -> (String, usize) {
        let mut words = text.split_whitespace();
        let name = words
            .next()
            .unwrap_or_else(|| error("empty instruction"))
            .to_owned();
        let mut args: Vec<String> = words.map(str::to_owned).collect();
        let mut arity = args.len();
        let mut varargs = false;
        if !name.starts_with(|c: char| c.is_ascii_lowercase())
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            error(&format!("Bad opcode name '{name}'"));
        }
        let operands = arity;
        for i in 0..operands {
            let arg = args[i].clone();
            if arg == "*" {
                if i != operands - 1 {
                    error("'*' must be the last operand");
                }
                args.pop();
                arity -= 1;
                varargs = true;
                break;
            }
            let arg = arg.trim_end_matches('?');
            for ty in arg.chars() {
                if ty == 'i' {
                    error(&format!(
                        "Argument {}: the 'i' type is not supported in specific instructions (use 'c')",
                        i + 1
                    ));
                }
                if !ARG_SIZE_TYPES.contains(ty) {
                    error(&format!("Argument {}: invalid type '{ty}'", i + 1));
                }
            }
        }
        if let Some(num) = self.gen_opnum.get(&(name.clone(), arity))
            && self.obsolete[*num]
        {
            error("specific instructions may not be specified for obsolete instructions");
        }
        // Expand operands with multiple types to multiple instructions.
        let mut res: Vec<Vec<String>> = vec![Vec::new()];
        for arg in &args {
            let old = res.clone();
            res = Vec::new();
            let (arg, marker) = match arg.strip_suffix('?') {
                Some(stripped) => (stripped, "?"),
                None => (arg.as_str(), ""),
            };
            for ty in arg.chars() {
                for previous in &old {
                    let mut next = previous.clone();
                    next.push(format!("{ty}{marker}"));
                    res.push(next);
                }
            }
        }
        // Store each specific instruction.
        let key = format!("{name}/{arity}");
        for specific_args in res {
            let arity = specific_args.len();
            if let Some((prev_arity, prev_loc)) = self.specific_op_arity.get(&name)
                && arity != *prev_arity
            {
                error(&format!(
                    "{name} defined with arity {arity}, but previously defined with arity {prev_arity} at {prev_loc}"
                ));
            }
            self.specific_op_arity
                .insert(name.clone(), (arity, loc.to_owned()));
            let printed = print_name(&name, &specific_args);
            if let Some(previous) = self.print_name.get(&printed) {
                error(&format!(
                    "{name} {specific_args:?}: already defined at {previous}"
                ));
            }
            self.print_name.insert(printed, loc.to_owned());
            self.specific_op
                .entry(key.clone())
                .or_default()
                .push(SpecificDef {
                    name: name.clone(),
                    varargs,
                    args: specific_args,
                });
        }
        (name, arity)
    }

    /// `parse_transformation`.
    fn parse_transformation(&mut self, loc: &str, text: &str) {
        let orig = text.split_whitespace().collect::<Vec<_>>().join(" ");
        let parts: Vec<&str> = split_trim(text, "=>");
        if parts.len() > 2 {
            error("only one '=>' operator is allowed");
        }
        let (from, to) = (parts[0], parts.get(1).copied().unwrap_or(""));
        let mut rest_var: Option<String> = None;
        let mut from_items = Vec::new();
        for piece in split_trim(from, "|") {
            if let Some((name, arglist)) = call_syntax(piece) {
                from_items.push(compile_transform_function(&name, &arglist));
            } else {
                let mut words = piece.split_whitespace();
                let name = words
                    .next()
                    .unwrap_or_else(|| error("empty instruction"))
                    .to_owned();
                let ops: Vec<&str> = words.collect();
                let (new_rest, item) = self.compile_transform(true, rest_var.clone(), &name, &ops);
                rest_var = new_rest;
                from_items.push(item);
            }
        }
        // Check for a function which should be called to provide the new instructions if the
        // left-hand side matched. Otherwise there is an explicit list of instructions.
        let to = to.trim();
        let mut to_items = Vec::new();
        if let Some((name, arglist)) = call_syntax_with_garbage(to) {
            to_items.push(compile_transform_function(&name, &arglist));
        } else if to == "_" {
            // _ means that instructions on the left side should be removed.
        } else {
            let pieces = split_trim(to, "|");
            if pieces.is_empty() || (pieces.len() == 1 && pieces[0].is_empty()) {
                error(
                    "the right-hand side of a transformation must not be empty; use _ to indicate that no instructions should be produced",
                );
            }
            for piece in pieces {
                let mut words = piece.split_whitespace();
                let name = words
                    .next()
                    .unwrap_or_else(|| error("empty instruction"))
                    .to_owned();
                let ops: Vec<&str> = words.collect();
                let (_, item) = self.compile_transform(false, rest_var.clone(), &name, &ops);
                to_items.push(item);
            }
        }
        to_items.reverse();
        self.transformations.push(Transformation {
            loc: loc.to_owned(),
            orig,
            from: from_items,
            to: to_items,
        });
    }

    /// `compile_transform`.
    fn compile_transform(
        &mut self,
        src: bool,
        mut rest_var: Option<String>,
        name: &str,
        ops: &[&str],
    ) -> (Option<String>, TrItem) {
        let mut arity = 0;
        let mut parsed = Vec::new();
        for op in ops {
            let mut list = tr_parse_op(src, op);
            if list.ty == "*" {
                rest_var = Some(list.var.clone());
            } else if rest_var.as_deref() == Some(list.var.as_str()) {
                list.ty = "*".to_owned();
            } else {
                arity += 1;
            }
            parsed.push(list);
        }
        if let Some(num) = self.gen_opnum.get(&(name.to_owned(), arity))
            && self.obsolete.get(*num).copied().unwrap_or(false)
        {
            error("obsolete function must not be used in transformations");
        }
        if src {
            self.is_transformed.insert((name.to_owned(), arity));
        }
        (
            rest_var,
            TrItem {
                name: name.to_owned(),
                arity,
                ops: parsed,
                call_args: Vec::new(),
            },
        )
    }

    /// The numbering after the input loop: `$num_file_opcodes`, then every generic instruction
    /// without a number in order of appearance.
    fn number_generic_ops(&mut self) {
        self.num_file_opcodes = self.gen_opname.len();
        for (name, arity) in std::mem::take(&mut self.unnumbered_generic) {
            let op_num = self.gen_opname.len();
            self.gen_opname.push(Some(name.clone()));
            self.gen_arity.push(arity);
            self.obsolete.push(false);
            self.gen_opnum.insert((name.clone(), arity), op_num);
            self.gen_arity_by_name.insert(name, arity);
        }
    }

    /// The checks of beam_makeops on specific instructions before the output is produced.
    fn verify_specific_ops(&self) {
        for (key, defs) in &self.specific_op {
            let arity: usize = key.rsplit('/').next().unwrap().parse().unwrap();
            if arity > MAX_SPEC_OPERANDS && defs.len() > 1 {
                error(&format!(
                    "{key} has {} specific instructions and more than {MAX_SPEC_OPERANDS} operands",
                    defs.len()
                ));
            }
            for def in defs {
                if def.args.iter().any(|a| a.trim_end_matches('?') == "r") {
                    error(&format!(
                        "specific instruction '{} {:?}' uses type 'r' which is is not supported for BeamAsm",
                        def.name, def.args
                    ));
                }
            }
        }
    }
}

fn word(text: &str) -> &str {
    let end = text
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(text.len());
    &text[..end]
}

/// `/^([\w_][\w\d_]+)=(.*)/`.
fn assignment(line: &str) -> Option<(&str, &str)> {
    let end = line.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))?;
    if end >= 2 && line[end..].starts_with('=') && !line[end..].starts_with("=>") {
        Some((&line[..end], &line[end + 1..]))
    } else {
        None
    }
}

/// `/^(\w[\w.]*)\(([^\)]*)\)\s*{/`.
fn c_block_start(line: &str) -> Option<(String, String)> {
    let first = line.chars().next()?;
    if !(first.is_ascii_alphanumeric() || first == '_') {
        return None;
    }
    let paren = line.find('(')?;
    let name = &line[..paren];
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    {
        return None;
    }
    let close = paren + line[paren..].find(')')?;
    if line[close + 1..].trim_start().starts_with('{') {
        Some((name.to_owned(), line[paren + 1..close].to_owned()))
    } else {
        None
    }
}

/// `parse_c_args`: the parameter names of a C block.
fn parse_c_args(text: &str) -> Vec<String> {
    text.split(',')
        .map(|part| {
            let part = part.trim();
            // The last word is the parameter name; types such as `Uint` or `BeamOpArg*` precede it.
            part.rsplit(|c: char| c.is_whitespace() || c == '*')
                .next()
                .unwrap_or("")
                .to_owned()
        })
        .filter(|name| !name.is_empty())
        .collect()
}

/// `/^(\w+)\s*:=\s*([\w.]+)\s*;\s*$/`.
fn combined_instruction(line: &str) -> bool {
    let Some(at) = line.find(":=") else {
        return false;
    };
    let left = line[..at].trim_end();
    let right = line[at + 2..].trim();
    !left.is_empty()
        && left.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && right.ends_with(';')
}

/// `m@^(-)?(\w+)/(\d)\s*$@`.
fn generic_op(text: &str) -> Option<(bool, &str, usize)> {
    let text = text.trim_end();
    let (obsolete, rest) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let slash = rest.rfind('/')?;
    let name = &rest[..slash];
    let arity = &rest[slash + 1..];
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    if arity.len() == 1 && arity.as_bytes()[0].is_ascii_digit() {
        Some((obsolete, name, arity.parse().unwrap()))
    } else {
        None
    }
}

/// Perl's `split(/\s*SEP\s*/, text)` for a literal separator.
fn split_trim<'a>(text: &'a str, sep: &str) -> Vec<&'a str> {
    text.split(sep).map(str::trim).collect()
}

/// `/^(\w+)\((.*?)\)/` on a left-hand side element.
fn call_syntax(piece: &str) -> Option<(String, Vec<String>)> {
    let paren = piece.find('(')?;
    let name = &piece[..paren];
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let close = piece.find(')')?;
    let arglist = &piece[paren + 1..close];
    Some((name.to_owned(), split_args(arglist)))
}

/// `/^(\w+)\((.*?)\)(.*)/` on the right-hand side, with the "garbage after call" check.
fn call_syntax_with_garbage(piece: &str) -> Option<(String, Vec<String>)> {
    let paren = piece.find('(')?;
    let name = &piece[..paren];
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let close = piece.find(')')?;
    if piece[close + 1..].chars().any(|c| !c.is_whitespace()) {
        error(&format!("garbage after call to '{name}()'"));
    }
    Some((name.to_owned(), split_args(&piece[paren + 1..close])))
}

fn split_args(text: &str) -> Vec<String> {
    if text.trim().is_empty() {
        return Vec::new();
    }
    text.split(',').map(|a| a.trim().to_owned()).collect()
}

/// `compile_transform_function`.
fn compile_transform_function(name: &str, args: &[String]) -> TrItem {
    TrItem {
        name: format!(".{name}"),
        arity: 0,
        ops: Vec::new(),
        call_args: args.to_vec(),
    }
}

/// `tr_parse_op`.
fn tr_parse_op(src: bool, op: &str) -> TrOp {
    let mut var = String::new();
    let mut ty = String::new();
    let mut cond = String::new();
    let mut cond_val = String::new();
    let mut rest = op;
    let pattern_type = |c: char| PATTERN_TYPES.contains(c);
    let construction_type = |c: char| {
        pattern_type(c)
            && format!("{COMPILER_TYPES}{LOADER_TYPES}").contains(c)
            && !matches!(c, 'f' | 'j' | 'o' | 'q')
    };

    // Get the variable name if any: /^(_?[A-Z]\w*)(.*)/
    {
        let bytes = rest.as_bytes();
        let start = if bytes.first() == Some(&b'_') { 1 } else { 0 };
        if bytes.get(start).is_some_and(u8::is_ascii_uppercase) {
            let end = rest[start..]
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .map_or(rest.len(), |i| i + start);
            var = rest[..end].to_owned();
            rest = &rest[end..];
            if let Some(after) = rest.strip_prefix('=') {
                rest = after;
            } else if !rest.trim().is_empty() {
                error("garbage after variable");
            } else {
                rest = "";
            }
        }
    }
    // Get the type if any: /^([a-z*]+)(.*)/
    {
        let end = rest
            .find(|c: char| !(c.is_ascii_lowercase() || c == '*'))
            .unwrap_or(rest.len());
        if end > 0 {
            ty = rest[..end].to_owned();
            rest = &rest[end..];
            if !src && ty.len() > 1 {
                error(&format!(
                    "{op}: only a single type is allowed on right side of transformations"
                ));
            }
            for letter in ty.chars() {
                if src && ty == "*" {
                    continue;
                }
                if type_bit(letter).is_none() {
                    error(&format!("{op}: not a type"));
                }
                if !pattern_type(letter) {
                    error(&format!(
                        "{op}: the type '{letter}' is not allowed in transformations"
                    ));
                }
                if !src && !construction_type(letter) {
                    error(&format!(
                        "{op}: type '{letter}' is not allowed on the right side of transformations"
                    ));
                }
            }
        }
    }
    // Get an optional condition. (In source.)
    if let Some(after) = rest.strip_prefix("==") {
        cond = "is_eq".to_owned();
        cond_val = after.to_owned();
        rest = "";
    } else if let Some(after) = rest.strip_prefix("$is_bif") {
        cond = "is_bif".to_owned();
        cond_val = "-1".to_owned();
        rest = after;
    } else if let Some(after) = rest.strip_prefix("$is_not_bif") {
        cond = "is_not_bif".to_owned();
        cond_val = "-1".to_owned();
        rest = after;
    } else if let Some(after) = rest.strip_prefix("$bif:") {
        // m@^\$bif:(\w+):(\w+)/(\d)(.*)@
        let (module, after) = split_word(after);
        let after = after
            .strip_prefix(':')
            .unwrap_or_else(|| error("bad $bif:"));
        let (function, after) = split_word(after);
        let after = after
            .strip_prefix('/')
            .unwrap_or_else(|| error("bad $bif:"));
        let arity = &after[..1];
        cond = "is_bif".to_owned();
        cond_val = if module == "erlang" {
            format!("BIF_{function}_{arity}")
        } else {
            format!("BIF_{module}_{function}_{arity}")
        };
        rest = &after[1..];
    } else if let Some(after) = rest.strip_prefix("$func:") {
        // m@^\$func:(\w+):(\w+)/([_\d])(.*)@
        let (module, after) = split_word(after);
        let after = after
            .strip_prefix(':')
            .unwrap_or_else(|| error("bad $func:"));
        let (function, after) = split_word(after);
        let after = after
            .strip_prefix('/')
            .unwrap_or_else(|| error("bad $func:"));
        let arity = if &after[..1] == "_" {
            "1024"
        } else {
            &after[..1]
        };
        cond = "is_func".to_owned();
        cond_val = format!("{module}:{function}:{arity}");
        rest = &after[1..];
    }
    // Get an optional value. (In destination.)
    let mut type_val = if ty == "x" {
        "1023".to_owned()
    } else if ty == "a" {
        "am_Empty".to_owned()
    } else {
        "0".to_owned()
    };
    if let Some(after) = rest.strip_prefix('=') {
        if src {
            error(&format!("{op}: value not allowed in source"));
        }
        if ty == "n" {
            error(&format!("{op}: the type 'n' must not be given a value"));
        }
        type_val = if after == "$MODULE" {
            "st->module".to_owned()
        } else {
            after.to_owned()
        };
        rest = "";
    }
    // Nothing more is allowed after the command.
    if !rest.trim().is_empty() {
        error(&format!("garbage '{rest}' after operand: {op}"));
    }
    // Check the conditions.
    if src {
        // `$cond and not $construction_type{$type}`, with `$type` the whole type string.
        if !cond.is_empty()
            && !(ty.chars().count() == 1 && construction_type(ty.chars().next().unwrap()))
        {
            error(&format!(
                "{op}: the type '{ty}' is not allowed to be compared with a literal value"
            ));
        }
    } else {
        if !cond.is_empty() {
            error(&format!("{op}: condition not allowed in destination"));
        }
        if !var.is_empty() && !ty.is_empty() {
            error(&format!(
                "{op}: variable name and type cannot be combined in destination"
            ));
        }
    }
    TrOp {
        var,
        ty,
        type_val,
        cond,
        cond_val,
    }
}

fn split_word(text: &str) -> (&str, &str) {
    let end = text
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(text.len());
    (&text[..end], &text[end..])
}
