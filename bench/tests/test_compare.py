"""Differential smoke tests against OTP 29.1.1."""

import shutil
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import compare  # noqa: E402


class ComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all(shutil.which(name) for name in ("erl", "erlc", "go", "cargo")):
            raise unittest.SkipTest("erl, erlc, go, and cargo are required for differential tests")
        compare.build(("rust", "go", "erts"))

    def test_all_kernel_results_match_erts(self):
        for name, (_, arguments) in compare.CASES.items():
            with self.subTest(name=name):
                values = {}
                for runtime in ("rust", "go", "erts"):
                    command = compare.command_for(runtime, name, arguments)
                    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    values[runtime], _ = compare.parse_output(result.stdout, name)
                self.assertTrue(compare.equal_result(values["erts"], values["rust"], name), values)
                self.assertTrue(compare.equal_result(values["erts"], values["go"], name), values)

    def test_rss_parsing(self):
        self.assertEqual(compare.parse_rss("123 maximum resident set size\n", "bytes"), 123)
        self.assertEqual(compare.parse_rss("MAX_RSS_KB=123\n", "kb"), 123 * 1024)


class HistoryTests(unittest.TestCase):
    def test_history_append_has_compact_schema_and_path(self):
        with tempfile.TemporaryDirectory() as temp:
            original_bench = compare.BENCH
            compare.BENCH = Path(temp)
            try:
                path = compare.append_history(
                    "fib", "go", {"status": "ok", "wall_median_ms": 2.0, "wall_stddev_ms": 0.1,
                                  "kernel_median_ms": 1.5, "peak_rss_median_bytes": 1048576},
                    machine="testbox", versions={"otp": "29.1.1", "erts": "17.1", "elixir": "1.20.4",
                                                  "go": "go1.test", "rust": "rustc test"},
                    runs=2, schedulers=4, cooldown=0, quick=False, sha="abc-dirty")
                self.assertEqual(path, Path(temp) / "history/testbox/otp-29.1.1/results.jsonl")
                record = json.loads(path.read_text())
                self.assertEqual(tuple(record), compare.HISTORY_FIELDS)
                self.assertEqual(record["peak_rss_mib"], 1.0)
                self.assertEqual(record["sha"], "abc-dirty")
                self.assertTrue(record["ok"])
            finally:
                compare.BENCH = original_bench

    def test_dirty_sha_suffix(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            (root / "tracked").write_text("clean\n")
            subprocess.run(["git", "add", "tracked"], cwd=root, check=True)
            subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.com",
                            "commit", "-qm", "seed"], cwd=root, check=True)
            clean_sha = compare.git_sha(root)
            (root / "tracked").write_text("dirty\n")
            self.assertEqual(compare.git_sha(root), clean_sha + "-dirty")

    def test_scoreboard_verdict_requires_strict_time_and_rss_win(self):
        go = {"median_kernel_ms": 10.0, "peak_rss_mib": 20.0}
        self.assertTrue(compare.scoreboard_verdict(
            {"median_kernel_ms": 9.0, "peak_rss_mib": 19.0}, go).startswith("PASS"))
        self.assertTrue(compare.scoreboard_verdict(
            {"median_kernel_ms": 10.0, "peak_rss_mib": 19.0}, go).startswith("FAIL"))
        self.assertIn("time 1.00×", compare.scoreboard_verdict(
            {"median_kernel_ms": 10.0, "peak_rss_mib": 20.0}, go))
        self.assertTrue(compare.scoreboard_verdict(
            {"median_kernel_ms": 9.0, "peak_rss_mib": 20.0}, go).startswith("FAIL"))


if __name__ == "__main__":
    unittest.main()


class EtsGateTest(unittest.TestCase):
    def test_ets_is_gated_against_erts(self):
        self.assertEqual(compare.gate_runtime("ets"), "erts")
        self.assertEqual(compare.gate_runtime("fib"), "go")
