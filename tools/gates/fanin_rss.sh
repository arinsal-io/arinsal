#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT="${TMPDIR:-/tmp}/fanin.json"

# Baseline measured before this change: 707.917 ms median kernel time at 9ee0470.
MAX_KERNEL_MS="$(python3 -c 'print(707.917 * 1.03)')"
MAX_RSS_MIB=210

cd "$ROOT"
cargo build --release
timeout 1200 python3 bench/compare.py \
  --runtimes arinsal --bench fanin --runs 3 --output "$OUTPUT"

python3 - "$OUTPUT" "$MAX_RSS_MIB" "$MAX_KERNEL_MS" <<'PY'
import json
import sys

path, max_rss, max_kernel = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
data = json.load(open(path, encoding="utf-8"))
result = data["benchmarks"]["fanin"]["runtimes"]["arinsal"]
if result.get("status") != "ok":
    raise SystemExit(f"fanin benchmark status: {result.get('status')}")
rss_mib = result["peak_rss_median_bytes"] / 1048576
kernel_ms = result["kernel_median_ms"]
print(f"fanin median_peak_rss_mib={rss_mib:.1f} median_kernel_ms={kernel_ms:.3f}")
if rss_mib > max_rss or kernel_ms > max_kernel:
    raise SystemExit(
        f"FAIL: limits are RSS <= {max_rss:.1f} MiB and kernel <= {max_kernel:.3f} ms"
    )
print("PASS: fan-in RSS and kernel time are within limits")
PY
