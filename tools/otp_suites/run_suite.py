#!/usr/bin/env python3
"""Run one vendored OTP suite against OTP and Arinsal and update RESULTS.md."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools/otp_suites"
OTP = ROOT / "tests/otp"
HELPERS = OTP / "lib/common_test/test_server"
RESULTS = TOOLS / "RESULTS.md"
RESULTS_BEAMASM = TOOLS / "RESULTS_BEAMASM.md"
PILOT = "big tuple map binary bs_match_bin bs_match_int bs_match_misc bs_match_tail bs_construct bs_utf fun exception guard receive ref num_bif list_bif float op small hash persistent_term atomics counters unique".split()


def run(cmd: list[str], timeout: int, **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["timeout", "--signal=KILL", str(timeout), *cmd],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        **kwargs,
    )


def compile_helpers(build: pathlib.Path) -> None:
    srcs = sorted(HELPERS.glob("*.erl")) + [TOOLS / "arinsal_case_timeout_cth.erl"]
    cp = run(["erlc", "-W0", "-I", str(HELPERS), "-o", str(build), *map(str, srcs)], 120)
    if cp.returncode:
        raise RuntimeError(f"helper compile failed ({cp.returncode}):\n{cp.stdout[-4000:]}")


def otp_root() -> pathlib.Path:
    proc = run(["erl", "-noshell", "-eval", "io:format(\"~s\",[code:root_dir()]),halt()."], 30)
    if proc.returncode:
        raise RuntimeError(f"cannot locate OTP root: {proc.stdout}")
    return pathlib.Path(proc.stdout.strip())


def build_native(name: str, source_dir: pathlib.Path) -> None:
    data = source_dir / f"{name}_SUITE_data"
    source = data / "Makefile.src"
    if not source.is_file():
        return
    root = otp_root()
    ei = next((root / "lib").glob("erl_interface-*/include"), None)
    ei_lib = next((root / "lib").glob("erl_interface-*/lib"), None)
    # macOS already declares sys_nerr/sys_errlist with const-qualified types;
    # use the system strerror() instead of port_test.c's legacy fallback.
    defs = "-DHAVE_ISFINITE -DHAVE_UNISTD_H -DHAVE_STRERROR" if name == "port" else "-DHAVE_ISFINITE -DHAVE_UNISTD_H"
    erts_internal = next(root.glob("erts-*/include/internal"), root / "usr/include/internal")
    values = {
        "CC": "clang", "LD": "clang", "SHLIB_LD": "clang",
        "CFLAGS": "-O2 -fPIC", "SHLIB_CFLAGS": "-O2 -fPIC",
        "CROSSLDFLAGS": "", "SHLIB_LDFLAGS": "-bundle -undefined dynamic_lookup",
        "SHLIB_LDLIBS": "", "SHLIB_EXTRA_LDFLAGS": "", "SHLIB_EXTRA_LDLIBS": "",
        "DEFS": defs, "LIBS": "", "EI_CFLAGS": f"-I{ei}" if ei else "",
        "EI_LDFLAGS": f"-L{ei_lib}" if ei_lib else "",
        "erl_include": str(root / "usr/include"),
        "erl_interface_include": str(ei) if ei else "",
        "erl_interface_eilib": str(ei_lib / "libei.a") if ei_lib and (ei_lib / "libei.a").is_file() else ("-lei" if ei else ""),
        "erl_interface_sock_libs": "", "erl_interface_threadlib": "-lpthread", "erl_interface_mk_include": str(ei_lib.parent / "src/eidefs.mk") if ei_lib else "",
        "erts_lib_make_ethread": str(erts_internal / "ethread.mk"),
        "erts_lib_make_internal": str(erts_internal / "erts_internal.mk"),
        "erts_lib_include_internal": str(erts_internal),
        "erts_lib_include_internal_generated": str(erts_internal),
        "WSL": "",
        "dll": ".so", "obj": ".o", "exe": "", "EMULATOR": "beam",
        "erl_name": "erl",
        "SHLIB_RULES": ".SUFFIXES: .so .o .c\n.c.so:\n\tclang -bundle -undefined dynamic_lookup -fPIC " + defs + " -DUSE_THREADS -D_THREAD_SAFE -D_REENTRANT -DPOSIX_THREADS -I" + str(erts_internal) + " -I" + str(root / "usr/include") + (" -I" + str(ei) if ei else "") + (" -L" + str(ei_lib) + " -lei" if ei_lib and name == "binary" else "") + " -o $@ $<",
    }
    makefile = source.read_text(encoding="utf-8")
    for key, value in values.items():
        makefile = makefile.replace(f"@{key}@", value)
    makefile = re.sub(r"^\s*include\s*$", "", makefile, flags=re.MULTILINE)
    generated = data / "Makefile"
    generated.write_text(makefile, encoding="utf-8")
    proc = run(["make", "-f", "Makefile"], 120, cwd=data)
    if proc.returncode:
        raise RuntimeError(f"native build failed for {name}_SUITE ({proc.returncode}):\n{proc.stdout[-4000:]}")


def suite_dir(name: str) -> pathlib.Path:
    for base in (OTP / "erts/emulator/test", OTP / "lib/kernel/test", OTP / "lib/stdlib/test"):
        if (base / f"{name}_SUITE.erl").is_file():
            return base
    raise ValueError(f"suite not found: {name}_SUITE.erl")


def run_one(exe: str, name: str, logdir: pathlib.Path, build: pathlib.Path, limit: int, beamasm: bool = False, extra: str = "") -> tuple[int, str]:
    logdir.mkdir(parents=True, exist_ok=True)
    original = suite_dir(name)
    with tempfile.TemporaryDirectory(prefix=f"otp-{name}-source-") as source_temp:
        directory = pathlib.Path(source_temp) / "test"
        shutil.copytree(original, directory)
        build_native(name, directory)
        # Precompile with erlc so both runtimes load the same .beam files; otherwise ct
        # compiles the suite inside the runtime under test (minutes in the interpreter).
        sources = sorted(str(p) for p in directory.glob("*.erl") if p.name == f"{name}_SUITE.erl" or not p.name.endswith("_SUITE.erl"))
        if sources:
            cp = run(["erlc", "-W0", "+debug_info", "-I", str(directory), "-I", str(HELPERS), "-pa", str(build), "-o", str(directory), *sources], 600)
            if cp.returncode:
                print(f"erlc warning for {name}: {cp.stdout[-800:]}", file=sys.stderr, flush=True)
        expr = (
            "R=ct:run_test([{dir,\"" + str(directory) + "\"},{suite," + name
            + "_SUITE},{logdir,\"" + str(logdir) + "\"}" + extra + "]), io:format(\"OTP_SUITE_RESULT=~p~n\",[R]), halt()."
        )
        cmd = [exe, "-noshell", "-pa", str(build), "-pa", str(directory), "-eval", expr]
        env = os.environ.copy()
        if beamasm:
            env["ARINSAL_BEAMASM"] = "1"
        result = run(cmd, limit, env=env)
        (logdir / "runner-output.log").write_text(result.stdout, encoding="utf-8", errors="replace")
        keep = os.environ.get("ARINSAL_RUNNER_LOG")
        if keep and exe != "erl":
            pathlib.Path(keep).write_text(result.stdout, encoding="utf-8", errors="replace")
        return result.returncode, result.stdout


def parse_results(logdir: pathlib.Path, suite: str) -> tuple[dict[str, tuple[str, str]], str]:
    logs = list(logdir.glob("ct_run*/**/suite.log"))
    if not logs:
        return {}, "no Common Test suite.log; " + (logdir / "runner-output.log").read_text(errors="replace")[-800:].replace("\n", " ")
    content = logs[0].read_text(encoding="utf-8", errors="replace")
    cases: dict[str, tuple[str, str]] = {}
    current: str | None = None
    current_module: str | None = None
    pending: str | None = None

    def save() -> None:
        nonlocal pending, current, current_module
        lifecycle = current in {"init_per_suite", "end_per_suite", "init_per_testcase", "end_per_testcase"} or bool(current and re.match(r"(?:init|end)_per_group", current))
        if current and current_module == suite + "_SUITE" and not lifecycle and pending is not None:
            m = re.match(r"(ok|passed|failed|skipped|auto_skipped):?\s*(.*)", pending)
            if m:
                status, reason = m.groups()
                cases[current] = ("ok" if status in ("ok", "passed") else status, reason.strip())
        pending = None
        current = None
        current_module = None

    for line in content.splitlines():
        if line.startswith("=case          "):
            save()
            case_ref = line.split(None, 1)[1].strip()
            current_module, _, current = case_ref.partition(":")
        elif line.startswith("=result        "):
            pending = line.split(None, 1)[1].strip()
        elif pending is not None and line.startswith("="):
            save()
        elif pending is not None and line[:1].isspace():
            pending += " " + line.strip()
    save()
    return cases, ""


def parse_elapsed(logdir: pathlib.Path, suite: str) -> dict[str, float]:
    """Per-case wall time (seconds) from the Common Test suite.log."""
    out: dict[str, float] = {}
    current = None
    for log in logdir.glob("ct_run*/**/suite.log"):
        for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("=case          "):
                module, _, case = line.split(None, 1)[1].strip().partition(":")
                current = case if module == suite + "_SUITE" else None
            elif line.startswith("=elapsed       ") and current:
                try:
                    out[current] = float(line.split(None, 1)[1].rstrip("s"))
                except ValueError:
                    pass
                current = None
    return out


# The erl reference result only changes with the vendored suite sources, so it is cached
# outside the repo and keyed by a hash of those sources.
ERL_CACHE = pathlib.Path(os.environ.get("ARINSAL_ERL_CACHE", pathlib.Path.home() / ".cache/arinsal/otp-suites"))


def erl_cache_key(name: str) -> str:
    h = hashlib.sha256()
    base = suite_dir(name)
    files = [base / f"{name}_SUITE.erl", *sorted(HELPERS.glob("*.erl"))]
    data = base / f"{name}_SUITE_data"
    if data.is_dir():
        files += sorted(p for p in data.rglob("*") if p.is_file() and p.name != "Makefile" and p.suffix not in (".o", ".so", ".beam"))
    for f in files:
        h.update(str(f.relative_to(OTP)).encode())
        h.update(f.read_bytes())
    return h.hexdigest()[:16]


def erl_reference(name: str, build: pathlib.Path, limit: int, use_cache: bool) -> tuple[int, dict[str, tuple[str, str]], str, dict[str, float]]:
    path = ERL_CACHE / f"{name}-{erl_cache_key(name)}.json"
    if use_cache and path.is_file():
        d = json.loads(path.read_text())
        return d["rc"], {k: tuple(v) for k, v in d["cases"].items()}, d["meta"], d["elapsed"]
    with tempfile.TemporaryDirectory(prefix=f"otp-{name}-erl-") as ed:
        erl_dir = pathlib.Path(ed)
        erc, eout = run_one("erl", name, erl_dir, build, limit)
        ecases, emeta = parse_results(erl_dir, name)
        if not ecases:
            emeta = emeta or eout[-600:].replace("\n", " ")
        elapsed = parse_elapsed(erl_dir, name)
    if ecases and erc == 0:
        ERL_CACHE.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"rc": erc, "cases": ecases, "meta": emeta, "elapsed": elapsed}))
    return erc, ecases, emeta, elapsed


def timeout_hook(elapsed: dict[str, float], floor: float, factor: float) -> str:
    limits = ",".join(f"'{c}'=>{int(max(floor, factor * t) * 1000)}" for c, t in sorted(elapsed.items()))
    return ",{ct_hooks,[{arinsal_case_timeout_cth,[{limits,#{" + limits + "}},{default," + str(int(floor * 1000)) + "}]}]}"


def first_failure(logdir: pathlib.Path) -> str:
    files = list(logdir.glob("ct_run*/**/suite.log"))
    if not files:
        out = (logdir / "runner-output.log").read_text(encoding="utf-8", errors="replace")
        return next((x.strip() for x in out.splitlines() if "Error" in x or "failed" in x.lower()), "run did not produce a suite log")
    for line in files[0].read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("=result        ") and not re.search(r"=result\s+(?:ok|passed)", line):
            return line.split(None, 1)[1].strip()
    return ""


def update_table(name: str, erl: dict[str, tuple[str, str]], arin: dict[str, tuple[str, str]], erl_meta: str, arin_meta: str, erl_rc: int, arin_rc: int, erl_dir: pathlib.Path, arin_dir: pathlib.Path, results_path: pathlib.Path = RESULTS) -> None:
    entries = []
    cases = sorted(set(erl) | set(arin))
    if not cases:
        entries.append(f"| `{name}_SUITE` | 0 | 0 | 0 | 0 | {arin_rc} | {erl_meta or 'no cases'}; {arin_meta or 'no Arinsal testcase results'} |")
    else:
        eok = sum(s == "ok" for s, _ in erl.values())
        aok = sum(s == "ok" for s, _ in arin.values())
        mismatch = [c for c in cases if erl.get(c, ("",))[0] == "ok" and arin.get(c, ("missing",))[0] != "ok"]
        def first_line(value: tuple[str, str]) -> str:
            status, reason = value
            summary = re.split(r", \[\{", reason, maxsplit=1)[0].strip()
            summary = summary[:180] + ("…" if len(summary) > 180 else "")
            return f"{status} {summary}".strip()

        detail = "; ".join(f"{c}: {first_line(arin.get(c, ('missing', '')))}" for c in mismatch)
        if not detail:
            detail = f"first failure: {first_failure(arin_dir)}" if arin_rc else "none"
        if not arin and cases and not arin_rc:
            suite_failure = first_failure(arin_dir)
            if suite_failure:
                detail = f"{detail}; suite-level: {suite_failure}"
        entries.append(f"| `{name}_SUITE` | {len(cases)} | {eok}/{len(cases)} | {aok}/{len(cases)} | {len(mismatch)} | {arin_rc} | {detail.replace('|', '&#124;')} |")
    old = results_path.read_text(encoding="utf-8") if results_path.exists() else "# OTP 29.1.1 suite pilot results\n\n| Suite | Cases | erl pass | Arinsal pass | erl-pass/Arinsal-not | Arinsal exit | First failure line / notes |\n|---|---:|---:|---:|---:|---:|---|\n"
    lines = [line for line in old.splitlines() if not line.startswith(f"| `{name}_SUITE` |")]
    lines.extend(" ".join(entry.split()) for entry in entries)
    header = lines[:3]
    rows = sorted((line for line in lines[3:] if line.count("|") >= 2), key=lambda line: line.split("|", 2)[1].strip())
    results_path.write_text("\n".join(header + rows) + "\n", encoding="utf-8")


def _acquire_global_slot() -> None:
    # Machine-wide limit on concurrent suite runs (each run keeps erl and Arinsal busy).
    import fcntl, os, time
    d = "/tmp/arinsal-suite-slots"
    os.makedirs(d, exist_ok=True)
    slots = int(os.environ.get("ARINSAL_SUITE_SLOTS", "2"))
    while True:
        for i in range(slots):
            fd = os.open(f"{d}/slot{i}.lock", os.O_CREAT | os.O_RDWR, 0o666)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                globals()["_SUITE_SLOT_FD"] = fd
                return
            except BlockingIOError:
                os.close(fd)
        time.sleep(3)


def main() -> int:
    _acquire_global_slot()
    parser = argparse.ArgumentParser()
    parser.add_argument("suite", help="suite basename without _SUITE, or all-pilot")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--arinsal", default=None, help="Arinsal binary (default target/release/arinsal, or target/fastrel/arinsal with --fast)")
    parser.add_argument("--fast", action="store_true", help="build and use the fastrel profile (quick incremental builds for iteration; gates use release)")
    parser.add_argument("--beamasm", action="store_true", help="set ARINSAL_BEAMASM=1 for the Arinsal run and write RESULTS_BEAMASM.md")
    parser.add_argument("--case", default="", help="comma-separated test cases: run only these on Arinsal, compare with cached erl, do not touch RESULTS.md")
    parser.add_argument("--group", default="", help="run only this group on Arinsal (same reporting as --case)")
    parser.add_argument("--no-erl-cache", action="store_true", help="rerun the erl reference instead of using the cache")
    parser.add_argument("--case-floor", type=float, default=20.0, help="minimum per-case limit in seconds")
    parser.add_argument("--case-factor", type=float, default=10.0, help="per-case limit = max(floor, factor * erl case time)")
    args = parser.parse_args()
    results_path = RESULTS_BEAMASM if args.beamasm else RESULTS
    suites = PILOT if args.suite == "all-pilot" else [args.suite.removesuffix("_SUITE")]
    partial = bool(args.case or args.group)
    arinsal = args.arinsal or str(ROOT / ("target/fastrel/arinsal" if args.fast else "target/release/arinsal"))
    if args.fast:
        result = run(["cargo", "build", "--profile", "fastrel", "-p", "arinsal-cli"], 1800, cwd=ROOT)
        if result.returncode:
            print(result.stdout[-4000:], file=sys.stderr)
            return result.returncode
    elif args.arinsal is None:
        # Always rebuild (a no-op when current) so a run never tests a stale binary.
        result = run(["cargo", "build", "--release", "-p", "arinsal-cli"], 1800, cwd=ROOT)
        if result.returncode:
            print(result.stdout[-4000:], file=sys.stderr)
            return result.returncode
    with tempfile.TemporaryDirectory(prefix="otp-suites-build-") as temp:
        build = pathlib.Path(temp)
        compile_helpers(build)
        for name in suites:
            try:
                erc, ecases, emeta, elapsed = erl_reference(name, build, args.timeout, not args.no_erl_cache)
                # Cases erl does not pass need no generous limit (e.g. erl itself hits a 9-minute timetrap).
                passing = {c: t for c, t in elapsed.items() if ecases.get(c, ("",))[0] == "ok"}
                extra = timeout_hook(passing, args.case_floor, args.case_factor)
                if args.case:
                    extra += ",{testcase,[" + ",".join(f"'{c.strip()}'" for c in args.case.split(",") if c.strip()) + "]}"
                if args.group:
                    extra += ",{group,'" + args.group + "'}"
                with tempfile.TemporaryDirectory(prefix=f"otp-{name}-arinsal-") as ad:
                    arin_dir = pathlib.Path(ad)
                    arc, aout = run_one(arinsal, name, arin_dir, build, args.timeout, args.beamasm, extra)
                    acases, ameta = parse_results(arin_dir, name)
                    if partial:
                        for c in sorted(acases):
                            e, a = ecases.get(c, ("missing", "")), acases[c]
                            mark = "OK " if a[0] == "ok" or e[0] != "ok" else "BAD"
                            print(f"{mark} {c}: erl={e[0]} arinsal={a[0]} {a[1][:300]}", flush=True)
                        apass = sum(s == "ok" for s, _ in acases.values())
                        print(f"{name}_SUITE partial: arinsal={apass}/{len(acases)} rc={arc}", flush=True)
                        if not acases:
                            print("  arinsal:", (ameta or aout[-600:].replace("\n", " "))[:600], flush=True)
                        continue
                    with tempfile.TemporaryDirectory(prefix=f"otp-{name}-erl-") as ed:
                        update_table(name, ecases, acases, emeta, ameta, erc, arc, pathlib.Path(ed), arin_dir, results_path)
                    epass = sum(s == "ok" for s, _ in ecases.values())
                    apass = sum(s == "ok" for s, _ in acases.values())
                    print(f"{name}_SUITE: erl={epass}/{len(ecases)} rc={erc}; arinsal={apass}/{len(acases)} rc={arc}", flush=True)
                    if not ecases:
                        print("  erl:", emeta[:600], flush=True)
                    if not acases:
                        print("  arinsal:", (ameta or aout[-600:].replace("\n", " "))[:600], flush=True)
            except Exception as exc:
                print(f"{name}_SUITE: harness error: {exc}", file=sys.stderr, flush=True)
                if partial:
                    continue
                with tempfile.TemporaryDirectory(prefix=f"otp-{name}-error-") as error_dir:
                    error_path = pathlib.Path(error_dir)
                    update_table(name, {}, {}, str(exc), str(exc), 1, 1, error_path, error_path, results_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
