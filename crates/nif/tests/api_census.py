#!/usr/bin/env python3
"""Compare OTP NIF API declarations with exported host binary symbols."""

import argparse
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[3]
HEADER = ROOT / "spec/otp-29.1.1/erl_nif_api_funcs.h"
parser = argparse.ArgumentParser()
parser.add_argument("binary", nargs="?", type=Path, default=ROOT / "target/debug/arinsal")
args = parser.parse_args()

declared = set(
    re.findall(
        r"ERL_NIF_API_FUNC_DECL\([^,]+,\s*(enif_[A-Za-z0-9_]+)",
        HEADER.read_text(),
    )
)
if not args.binary.is_file():
    print(f"missing host executable: {args.binary}; build arinsal-cli first", file=sys.stderr)
    sys.exit(2)
nm = subprocess.run(["nm", str(args.binary)], check=True, capture_output=True, text=True)
implemented = set(re.findall(r"\b_?(enif_[A-Za-z0-9_]+)$", nm.stdout, re.MULTILINE))

missing = sorted(declared - implemented)
print(
    f"API declarations: {len(declared)}; exported symbols: "
    f"{len(declared & implemented)}; missing: {len(missing)}"
)
if missing:
    print("\n".join(missing))
    sys.exit(1)
