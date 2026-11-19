#!/usr/bin/env python3
"""Scan OTP's x86 BeamAsm source for assembler calls and used operand shapes."""

from __future__ import annotations

import argparse
import collections
import pathlib
import re

DEFAULT_ROOT = pathlib.Path(__file__).resolve().parents[2] / "ref/otp-29/erts/emulator/beam/jit/x86"
CALL = re.compile(r"\ba\.([A-Za-z_]\w*)\s*\(")
FEATURE = re.compile(r"CpuFeatures::X86::k(BMI2|LZCNT|POPCNT|AVX|MOVBE)")
FEATURE_MNEMONICS = {
    "BMI2": {"bzhi", "mulx", "pext", "sarx", "shrx"},
    "LZCNT": {"lzcnt"},
    "POPCNT": {"popcnt"},
    "AVX": {"vandpd", "vcvtsi2sd", "vmovdqu", "vmovq", "vmovsd", "vmovups", "vpermilpd", "vpinsrq", "vptest", "vpxor", "vucomisd", "vzeroupper"},
    "MOVBE": {"movbe"},
}
BRANCHES = {"call", "jmp", "ja", "jae", "jb", "jbe", "je", "jg", "jge", "jl", "jle", "jne", "jnz", "jo", "js", "jz"}


def arguments(source: str, open_paren: int) -> list[str]:
    depth, start, args = 1, open_paren + 1, []
    quote = None
    for pos in range(open_paren + 1, len(source)):
        char = source[pos]
        if quote:
            if char == quote and source[pos - 1] != "\\":
                quote = None
            continue
        if char in "\"'":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                tail = source[start:pos].strip()
                if tail:
                    args.append(tail)
                return args
        elif char == "," and depth == 1:
            args.append(source[start:pos].strip())
            start = pos + 1
    return []


def operand_shape(expr: str, symbol_types: dict[str, str], mnemonic: str, index: int) -> str:
    e = " ".join(expr.split())
    if re.search(r"\b(?:imm|Imm)\s*\(", e):
        return "Imm (asmjit-selected width)"
    if re.search(r"\b(?:xmm|ymm|zmm)\d+\b", e):
        return "Xmm/Ymm"
    size = re.search(r"\b(byte|word|dword|qword|xmmword|ymmword)_ptr\s*\(", e)
    if size:
        return f"Mem/{size.group(1)}"
    if re.fullmatch(r"[A-Za-z_]\w*", e) and e in symbol_types:
        return symbol_types[e]
    view = re.fullmatch(r"([A-Za-z_]\w*)\.r(8|16|32|64)\(\)", e)
    if view:
        return f"Gp{view.group(2)}"
    helper_mem = re.search(r"\b(?:emit_boxed_val|getArgRef|getXRef|getFRef|getYRef|getSchedulerRegRef|getRuntimeStackRef|getCPRef|getCARRef|getCDRRef|getInitialSPRef)\s*\(", e)
    if helper_mem:
        return "Mem/typed by helper"
    if re.search(r"\bx86::(?:ptr|ptr_abs|Mem)\s*\(", e):
        return "Mem/unsized"
    if (mnemonic in BRANCHES | {"cmova", "cmovae", "cmovbe", "cmove", "cmovg", "cmovne", "cmovns", "cmovnz", "cmovs", "bind", "embed_label"}
            and index == 0):
        return "label/address"
    if re.fullmatch(r"x86::[a-z][a-z0-9]*", e):
        return "Gp64"
    if re.search(r"\b(?:clone_adjusted|get_handle_call_fun_error)\s*\(", e):
        return "Mem/typed by helper" if "clone_adjusted" in e else "Imm (address expression)"
    if e.startswith("AlignMode::"):
        return "AlignMode"
    if "text_section()" in e or e in {"rodata", "code"}:
        return "Section"
    if re.fullmatch(r"[A-Z][A-Z0-9_]*|RET_[A-Za-z0-9_]+", e):
        return "Imm (constant expression)"
    if any(op in e for op in ("<<", "-", "+", "sizeof(", "header_heap_bits(", "make_pos_bignum_header(", "make_neg_bignum_header(")):
        return "Imm (constant expression)"
    if re.fullmatch(r"[-+]?\d+", e):
        return "Imm (literal)"
    return "expression"


def scan(root: pathlib.Path):
    calls = []
    feature_sites = collections.defaultdict(set)
    paths = [path for path in sorted(root.rglob("*")) if path.suffix in {".cpp", ".hpp"}]
    sources = {path: path.read_text(errors="replace") for path in paths}
    for path, source in sources.items():
        common = sources.get(root / "beam_asm.hpp", "")
        symbol_source = source + "\n" + common
        symbol_types = {}
        for kind in ("Gp", "Mem"):
            for name in re.findall(rf"\bx86::{kind}\s+([A-Za-z_]\w*)", symbol_source):
                suffix = name[-1:] if kind == "Gp" and name[-1:] in "bwdq" else "q"
                width = {"b": "8", "w": "16", "d": "32", "q": "64"}[suffix]
                symbol_types[name] = f"Gp{width}" if kind == "Gp" else "Mem/typed"
            for declaration in re.findall(rf"\bx86::{kind}\s+([^;]+);", symbol_source):
                for item in declaration.split(","):
                    name = re.match(r"\s*([A-Za-z_]\w*)", item)
                    if name:
                        symbol = name.group(1)
                        suffix = symbol[-1:] if kind == "Gp" and symbol[-1:] in "bwdq" else "q"
                        width = {"b": "8", "w": "16", "d": "32", "q": "64"}[suffix]
                        symbol_types[symbol] = f"Gp{width}" if kind == "Gp" else "Mem/typed"
        for width, size in (("byte", "8"), ("word", "16"), ("dword", "32"), ("qword", "64")):
            for name in re.findall(rf"\bx86::Gp\s+(\w+?)_{width}\b", symbol_source):
                symbol_types[name] = f"Gp{size}"
        for name in re.findall(r"\bLabel\s+([A-Za-z_]\w*)", symbol_source):
            symbol_types[name] = "label/address"
        for name in re.findall(r"\bTMP_MEM\d+[bwdq]\b", symbol_source):
            suffix = name[-1]
            size = {"b": "byte", "w": "word", "d": "dword", "q": "qword"}[suffix]
            symbol_types[name] = f"Mem/{size}"
        for _ in range(2):
            for name, target in re.findall(r"\b(?:const\s+)?auto\s*&?\s*(\w+)\s*=\s*(\w+)\s*;", symbol_source):
                if target in symbol_types:
                    symbol_types[name] = symbol_types[target]
        for match in CALL.finditer(source):
            line = source.count("\n", 0, match.start()) + 1
            name = match.group(1)
            args = arguments(source, match.end() - 1)
            shapes = tuple(operand_shape(arg, symbol_types, name, i) for i, arg in enumerate(args))
            calls.append((name, path.name, line, shapes))
        for line, text in enumerate(source.splitlines(), 1):
            if "hasCpuFeature" in text:
                for feature in FEATURE.findall(text):
                    feature_sites[feature].add(f"{path.name}:{line}")
    return calls, feature_sites


def write_forms(path: pathlib.Path, calls, feature_sites):
    grouped = collections.defaultdict(collections.Counter)
    for name, _file, _line, shapes in calls:
        grouped[name][", ".join(shapes) if shapes else "(no operands)"] += 1
    out = ["# x86 BeamAsm encoder operand forms", "", "Reference: OTP-29.1.1 `erts/emulator/beam/jit/x86/`.",
           "Generated by `python3 tools/x86_scan/scan.py --forms docs/design/x86_encoder_forms.md`.",
           "Forms are source-used asmjit operand shapes; immediate byte width is selected by asmjit from value and encoding.", "",
           "## Forms by mnemonic", "", "| Mnemonic | Used operand forms (call count) | CPU feature gate |", "|---|---|---|"]
    for name in sorted(grouped):
        forms = "<br>".join(f"`{form}` ({count})" for form, count in sorted(grouped[name].items()))
        gates = ", ".join(feature for feature in ("BMI2", "LZCNT", "POPCNT", "AVX", "MOVBE") if name in FEATURE_MNEMONICS[feature]) or "—"
        out.append(f"| `{name}` | {forms} | {gates} |")
    out += ["", "## CPU feature checks", "", "Runtime checks branch around emission of feature-specific alternatives. Exact check sites are listed below. OTP has no direct `kPOPCNT` check in this x86 JIT source; `popcnt` is emitted unconditionally.", ""]
    for feature in ("BMI2", "LZCNT", "POPCNT", "AVX", "MOVBE"):
        sites = ", ".join(f"`{site}`" for site in sorted(feature_sites[feature])) or "no runtime checks found"
        forms = ", ".join(f"`{name}`" for name in sorted(FEATURE_MNEMONICS[feature])) or "none"
        out.append(f"- `CpuFeatures::X86::k{feature}`: {sites}; associated forms: {forms}.")
    out += ["", "Register widths follow asmjit Gp aliases; explicit pointer constructors retain their byte/word/dword/qword/vector widths. Compound helper expressions stay `expression` where the source type cannot be inferred syntactically.", ""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(out))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=pathlib.Path, default=DEFAULT_ROOT)
    parser.add_argument("--calls", type=pathlib.Path, help="write every call occurrence as TSV")
    parser.add_argument("--forms", type=pathlib.Path, help="write operand-form inventory markdown")
    args = parser.parse_args()
    calls, feature_sites = scan(args.root)
    if args.calls:
        args.calls.parent.mkdir(parents=True, exist_ok=True)
        with args.calls.open("w") as stream:
            stream.write("mnemonic\tfile\tline\toperand_form\n")
            for name, file, line, shapes in calls:
                stream.write(f"{name}\t{file}\t{line}\t{', '.join(shapes) or '(no operands)'}\n")
    if args.forms:
        write_forms(args.forms, calls, feature_sites)
    print(f"{len(calls)} calls; {len(set(row[0] for row in calls))} distinct names")


if __name__ == "__main__":
    main()
