#!/usr/bin/env python3
"""Inventory source-level Rust `unsafe` sites without counting comments or literals.

Usage: python3 tools/unsafe_census/census.py [--csv PATH] [--json PATH] [--check]
The CSV is the reviewable, one-row-per-site ledger. Classifications are
heuristic primary reasons; inspect a row before using it to change an API.
`--check` exits 1 when a crate exceeds tools/unsafe_census/baseline.json.
"""

import argparse
import collections
import csv
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2]
CRATES = ROOT / "crates"
DEFAULT_BASELINE = pathlib.Path(__file__).resolve().parent / "baseline.json"


def mask_non_code(source):
    """Replace comments and literals with spaces while retaining offsets/newlines."""
    out = list(source)
    n = len(source)

    def hide(start, end):
        for j in range(start, end):
            if source[j] != "\n":
                out[j] = " "

    i = 0
    while i < n:
        if source.startswith("//", i):
            end = source.find("\n", i)
            end = n if end < 0 else end
            hide(i, end)
            i = end
        elif source.startswith("/*", i):
            start = i
            i += 2
            depth = 1
            while i < n and depth:
                if source.startswith("/*", i):
                    depth += 1
                    i += 2
                elif source.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            hide(start, i)
        else:
            raw = re.match(r'(?:br|r)(#+)?"', source[i:])
            if raw:
                start = i
                hashes = raw.group(1) or ""
                i += len(raw.group())
                end = source.find('"' + hashes, i)
                i = n if end < 0 else end + len(hashes) + 1
                hide(start, i)
            elif source[i] == '"' or source.startswith('b"', i):
                start = i
                i += 2 if source.startswith('b"', i) else 1
                while i < n:
                    if source[i] == "\\":
                        i += 2
                    elif source[i] == '"':
                        i += 1
                        break
                    else:
                        i += 1
                hide(start, min(i, n))
            elif source[i] == "'" or source.startswith("b'", i):
                # A lifetime has no closing quote before its next token.
                start = i
                quote = i + 1 if source.startswith("b'", i) else i
                j = quote + 1
                if j < n and source[j] == "\\":
                    j += 2
                else:
                    j += 1
                if j < n and source[j] == "'":
                    i = j + 1
                    hide(start, i)
                else:
                    i += 1
            else:
                i += 1
    return "".join(out)


def body_at(code, pos):
    opening = code.find("{", pos)
    semicolon = code.find(";", pos)
    if opening < 0 or (semicolon >= 0 and semicolon < opening):
        return code[pos : semicolon + 1 if semicolon >= 0 else len(code)]
    depth = 0
    for end in range(opening, len(code)):
        if code[end] == "{":
            depth += 1
        elif code[end] == "}":
            depth -= 1
            if depth == 0:
                return code[pos : end + 1]
    return code[pos:]


def classify(crate, path, kind, context):
    s = context.lower()
    p = str(path).lower()
    if kind == "attribute":
        return "NIF/driver C ABI"
    if kind == "impl" and re.search(r"\b(?:send|sync)\b", s[:150]):
        return "Send/Sync impl"
    if "static mut" in s[:150] or crate == "nif-tty" and "cur_term" in s:
        return "static mut"
    if re.search(r"\b(?:transmute|transmute_copy|union)\b", s):
        return "transmute/union punning"
    if "get_unchecked" in s or "unwrap_unchecked" in s or "unreachable_unchecked" in s:
        return "unchecked indexing/speed"
    if crate in ("jit", "opt") and (crate == "jit" or "backend.rs" in p) or "jit_" in p or "exec_mem" in p or "mprotect" in s:
        return "JIT code/memory"
    if "src/gc.rs" in p and crate == "term":
        return "GC moving/rooting"
    if kind == "extern" and crate in ("term", "bifs") or crate == "term" and "mmap" in s:
        return "syscalls/libc"
    if re.search(r"\b(?:libc|syscall|ioctl|fcntl|setsockopt|getsockopt|poll|recvmsg|sendmsg|sigaction|pthread_|dlopen|dlsym)\b", s) and (crate.startswith("nif-") or crate in ("vm", "nif", "re")):
        return "syscalls/libc"
    if kind == "extern" or "extern \"c\"" in s[:160] or crate in ("nif", "nif-tty", "nif-socket", "nif-zlib", "nif-file", "nif-buffer", "re") and re.search(r"\b(?:enif_|erl_nif|nif_|cstr|cstring|ffi|erlangnif|ar_re_)", s):
        return "NIF/driver C ABI"
    if "x.as_" in s or "p.x" in s or "self.x" in s or "register" in s or "stack_slot" in s or "y.as_" in s or (crate == "vm" and "src/lib.rs" in p and re.search(r"\b(?:x|stop)\.add\(", s)):
        if crate == "vm":
            return "interpreter register file"
    if crate == "vm" and ("collect(" in s or "gc_" in s or "root" in s or "heap_cursor" in s or "htop" in s):
        return "GC moving/rooting"
    if re.search(r"\b(?:from_raw_parts|from_raw|as_ptr|as_mut_ptr|ptr\.add|\.offset\(|\.offset_from\(|\.read\(|\.write\(|raw_ptr|cons_ref|tuple_ref|binary_ref|big_ref|float_ref|record_ref|fun_ref|magic_ref|boxed|heap|term|fragment|slice::|non_null)\b", s):
        return "raw term/heap pointer"
    if crate in ("term", "bifs", "bits", "maps", "ets", "arith", "loader", "opt", "pterm"):
        return "raw term/heap pointer"
    if crate == "vm":
        return "interpreter register file" if "src/lib.rs" in p else "raw term/heap pointer"
    if crate.startswith("nif") or crate == "re":
        return "NIF/driver C ABI"
    return "raw term/heap pointer"


def inventory():
    rows = []
    for path in sorted(CRATES.rglob("*.rs")):
        source = path.read_text()
        code = mask_non_code(source)
        crate = path.relative_to(CRATES).parts[0]
        for match in re.finditer(r"\bunsafe\b", code):
            pos = match.start()
            tail = code[match.end() :]
            next_token = re.search(r"\S+", tail)
            token = next_token.group() if next_token else ""
            if token.startswith("impl"):
                kind = "impl"
            elif token.startswith("fn") or token.startswith("pub") or token.startswith("const") or token.startswith("async"):
                kind = "fn"
            elif token.startswith("extern"):
                kind = "extern"
            elif token.startswith("trait"):
                kind = "trait"
            elif token.startswith("{"):
                kind = "block"
            elif token.startswith("(no_mangle)") or token.startswith("(export_name"):
                kind = "attribute"
            else:
                kind = "other"
            context = body_at(code, pos)
            # A large enclosing unsafe item is classified from its declaration
            # and first operations, not unrelated functions later in that item.
            if kind != "block":
                context = context[:1200]
            line = source.count("\n", 0, pos) + 1
            original_line = source.splitlines()[line - 1].strip()
            reason = classify(crate, path.relative_to(ROOT), kind, context)
            rows.append({"crate": crate, "file": str(path.relative_to(ROOT)), "line": line,
                         "kind": kind, "reason": reason, "source": original_line[:180]})
    return rows


def crate_names():
    """Package directory names under crates/, including those with zero sites."""
    return sorted(
        path.name
        for path in CRATES.iterdir()
        if path.is_dir() and (path / "Cargo.toml").is_file()
    )


def package_counts(rows):
    """Map each package to its site count. Also return sites outside a package."""
    counts = collections.Counter(row["crate"] for row in rows)
    names = crate_names()
    present = {name: counts.pop(name, 0) for name in names}
    return present, dict(counts)


def load_maxima(path):
    data = json.loads(path.read_text())
    raw = data["max_sites"]
    maxima = {}
    for key, value in raw.items():
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise SystemExit(
                f"census check: baseline max_sites.{key} must be a non-negative integer"
            )
        maxima[key] = value
    return maxima


def evaluate_baseline(package_counts_map, maxima):
    """Return (failures, notes). A count under its maximum is allowed.

    `package_counts_map` includes every on-disk package. A missing baseline
    key or a baseline key whose directory is gone is a failure, so a new
    crate cannot appear without an explicit maximum.
    """
    failures = []
    notes = []
    packages = set(package_counts_map)
    for crate in sorted(packages - set(maxima)):
        failures.append(
            f"{crate}: {package_counts_map[crate]} sites but the crate is missing from the baseline"
        )
    for crate in sorted(set(maxima) - packages):
        failures.append(
            f"{crate}: baseline maximum is {maxima[crate]} but crates/{crate} is gone"
        )
    for crate in sorted(packages & set(maxima)):
        actual = package_counts_map[crate]
        limit = maxima[crate]
        if actual > limit:
            failures.append(
                f"{crate}: {actual} sites exceeds baseline {limit} (+{actual - limit})"
            )
        elif actual < limit:
            notes.append(
                f"{crate} has {actual} sites, below baseline {limit}; "
                "lower max_sites after the cleanup"
            )
    return failures, notes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=pathlib.Path)
    parser.add_argument("--json", type=pathlib.Path)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if any crate exceeds the per-crate maximum in the baseline",
    )
    parser.add_argument(
        "--baseline",
        type=pathlib.Path,
        default=DEFAULT_BASELINE,
        help="per-crate maxima JSON (default: tools/unsafe_census/baseline.json)",
    )
    args = parser.parse_args()
    rows = inventory()
    if args.csv:
        if not rows:
            raise SystemExit("census: refusing to write a CSV with zero sites")
        with args.csv.open("w", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
    pair_counts = collections.Counter((r["crate"], r["reason"]) for r in rows)
    kinds = collections.Counter(r["kind"] for r in rows)
    report = {"total": len(rows), "kinds": dict(sorted(kinds.items())),
              "by_crate_reason": [{"crate": c, "reason": r, "count": n}
                                  for (c, r), n in sorted(pair_counts.items())]}
    if args.json:
        args.json.write_text(json.dumps(report, indent=2) + "\n")
    print(f"sites: {len(rows)}; kinds: {dict(kinds)}")
    by_crate = collections.Counter(r["crate"] for r in rows)
    by_reason = collections.Counter(r["reason"] for r in rows)
    print("crates:", dict(by_crate.most_common()))
    print("reasons:", dict(by_reason.most_common()))
    if not args.check:
        return
    if not args.baseline.is_file():
        raise SystemExit(f"census check: baseline not found: {args.baseline}")
    present, extra = package_counts(rows)
    failures, notes = evaluate_baseline(present, load_maxima(args.baseline))
    for crate, count in sorted(extra.items()):
        failures.append(f"{crate}: {count} sites are outside a crate package")
    if failures:
        print("census check: FAIL")
        for line in failures:
            print(f"  {line}")
        raise SystemExit(1)
    print("census check: ok")
    for line in notes:
        print(f"note: {line}")


if __name__ == "__main__":
    main()
