"""Compare default and fastalloc on the copied pf_exec mechanism kernels."""

import csv
import io
import os
import statistics
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / "experiments/perf/jit_backend_adr/target/release/pf-exec-probe"

for mode in ("default", "fast"):
    results = {}
    for _ in range(5):
        env = dict(os.environ)
        if mode == "fast":
            env["ADR_CL_FAST"] = "1"
        output = subprocess.check_output([BIN, "200000"], env=env, text=True, timeout=30)
        for row in csv.DictReader(io.StringIO(output)):
            if row["engine"] == "cranelift" or (mode == "default" and row["engine"] == "a64"):
                results.setdefault((row["engine"], row["kernel"]), []).append(row)
    for (engine, kernel), rows in results.items():
        times = [float(row["ns_per_unit"]) for row in rows]
        print(f"{mode} {engine} {kernel}: median_ns={statistics.median(times):.3f} "
              f"range={min(times):.3f}-{max(times):.3f} "
              f"code_bytes={rows[0]['code_bytes']}")
