#!/usr/bin/env python3
"""Format bif_gaps_probe results into REPORT.md."""

import json
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True


def sanitize_md(text: str, max_len: int = 120) -> str:
    cleaned = text.replace("\r\n", "\\n").replace("\n", "\\n").replace("|", "\\|")
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) > max_len:
        return cleaned[: max_len - 3] + "..."
    return cleaned


def main():
    if len(sys.argv) < 3:
        print("Usage: reporter.py <results.jsonl> <output_report.md>", file=sys.stderr)
        sys.exit(1)

    results_path = Path(sys.argv[1])
    report_path = Path(sys.argv[2])
    retries_arg = int(sys.argv[3]) if len(sys.argv) > 3 else None

    records = []
    with open(results_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))

    retried_count = (
        retries_arg
        if retries_arg is not None
        else sum(1 for rec in records if rec.get("retried", False))
    )

    # 1. Missing BIFs table: M:F/A, count, first caller
    bif_stats = {}  # bif -> {"count": int, "first_caller": str}
    for rec in records:
        for item in rec.get("unsupported_bifs", []):
            bif = item["bif"]
            caller = item["caller"]
            if bif not in bif_stats:
                bif_stats[bif] = {"count": 1, "first_caller": caller}
            else:
                bif_stats[bif]["count"] += 1

    # 2. Result mismatches: snippet, erts output, Arinsal output
    mismatches = []
    for rec in records:
        erts_out = rec["erts_out"].strip()
        arinsal_out = rec["arinsal_out"].strip()
        erts_code = rec["erts_code"]
        arinsal_code = rec["arinsal_code"]

        is_mismatch = (erts_out != arinsal_out) or (erts_code != arinsal_code)
        if is_mismatch:
            # Determine readable Arinsal output representation
            if arinsal_out:
                arinsal_repr = arinsal_out
            else:
                # Look for meaningful error in stderr
                err_lines = [
                    l.strip()
                    for l in rec["arinsal_err"].splitlines()
                    if l.strip()
                    and not l.startswith("Crash dump is being written to:")
                ]
                # Priority: unsupported BIF line, or Runtime terminating line, or first non-empty line
                unsupported_line = next(
                    (l for l in err_lines if "unsupported BIF" in l), None
                )
                runtime_line = next(
                    (l for l in err_lines if "Runtime terminating" in l), None
                )
                failed_line = next(
                    (l for l in err_lines if "Error! Failed to eval:" in l), None
                )
                if unsupported_line:
                    arinsal_repr = f"Error: {unsupported_line}"
                elif runtime_line:
                    arinsal_repr = f"Error: {runtime_line}"
                elif failed_line:
                    arinsal_repr = f"Error: {failed_line}"
                elif err_lines:
                    arinsal_repr = f"Error: {err_lines[0]}"
                else:
                    arinsal_repr = f"Exit code {arinsal_code} (no output)"

            erts_repr = erts_out if erts_out else f"Exit code {erts_code} (no output)"

            mismatches.append(
                {
                    "snippet": rec["snippet"],
                    "erts_output": erts_repr,
                    "arinsal_output": arinsal_repr,
                }
            )

    # Generate Markdown report
    lines = [
        "# BIF Gaps Probe Report",
        "",
        "## Summary",
        "",
        f"- Total snippets evaluated: {len(records)}",
        f"- Result matches: {len(records) - len(mismatches)}",
        f"- Result mismatches: {len(mismatches)}",
        f"- Retried snippets: {retried_count}",
        f"- Distinct missing BIFs observed: {len(bif_stats)}",
        "",
        "## Missing BIFs",
        "",
    ]

    if bif_stats:
        lines.extend(
            [
                "| M:F/A | Count | First Caller |",
                "|---|---:|---|",
            ]
        )
        # Sort by count descending, then BIF name
        sorted_bifs = sorted(
            bif_stats.items(), key=lambda kv: (-kv[1]["count"], kv[0])
        )
        for bif, stat in sorted_bifs:
            lines.append(
                f"| `{sanitize_md(bif)}` | {stat['count']} | `{sanitize_md(stat['first_caller'])}` |"
            )
    else:
        lines.append("No unsupported BIF stderr lines observed.")

    lines.extend(
        [
            "",
            "## Result Mismatches",
            "",
        ]
    )

    if mismatches:
        lines.extend(
            [
                "| Snippet | ERTS Output | Arinsal Output |",
                "|---|---|---|",
            ]
        )
        for m in mismatches:
            snip_md = f"`{sanitize_md(m['snippet'], 80)}`"
            erts_md = f"`{sanitize_md(m['erts_output'], 80)}`"
            arin_md = f"`{sanitize_md(m['arinsal_output'], 100)}`"
            lines.append(f"| {snip_md} | {erts_md} | {arin_md} |")
    else:
        lines.append("No result mismatches observed.")

    lines.append("")

    report_content = "\n".join(lines)
    report_path.write_text(report_content, encoding="utf-8")
    print(f"Wrote report to {report_path}")


if __name__ == "__main__":
    main()
