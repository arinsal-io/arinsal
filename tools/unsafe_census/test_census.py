import json
import unittest

from pathlib import Path

from census import classify, crate_names, evaluate_baseline, mask_non_code


class MaskingTests(unittest.TestCase):
    def test_nested_comments_literals_and_lifetimes(self):
        source = '''// unsafe { hidden }
/* unsafe /* unsafe */ unsafe */
let text = r###"unsafe { hidden }"###;
let byte = b'!';
fn borrow<'a>(x: &'a u8) { unsafe { visible() } }
'''
        code = mask_non_code(source)
        self.assertEqual(code.count("unsafe"), 1)
        self.assertIn("'a", code)
        self.assertEqual(code.count("\n"), source.count("\n"))

    def test_primary_invariant_examples(self):
        self.assertEqual(
            classify("term", Path("crates/term/src/gc.rs"), "block", "unsafe { *source }"),
            "GC moving/rooting",
        )
        self.assertEqual(
            classify("vm", Path("crates/vm/src/lib.rs"), "block", "unsafe { *x.add(i) }"),
            "interpreter register file",
        )
        self.assertEqual(
            classify("nif", Path("crates/nif/src/terms.rs"), "attribute", "unsafe(no_mangle)"),
            "NIF/driver C ABI",
        )


class BaselineTests(unittest.TestCase):
    def test_increase_fails_and_decrease_is_a_note(self):
        counts = {"arith": 10, "args": 0}
        maxima = {"arith": 9, "args": 0, "beam": 0}
        failures, notes = evaluate_baseline(counts, maxima)
        self.assertEqual(
            failures,
            [
                "beam: baseline maximum is 0 but crates/beam is gone",
                "arith: 10 sites exceeds baseline 9 (+1)",
            ],
        )
        self.assertEqual(notes, [])

        failures, notes = evaluate_baseline({"arith": 7, "args": 0}, {"arith": 9, "args": 0})
        self.assertEqual(failures, [])
        self.assertEqual(
            notes,
            ["arith has 7 sites, below baseline 9; lower max_sites after the cleanup"],
        )

    def test_missing_crate_key_fails(self):
        failures, notes = evaluate_baseline({"fresh": 0}, {})
        self.assertEqual(
            failures,
            ["fresh: 0 sites but the crate is missing from the baseline"],
        )
        self.assertEqual(notes, [])

    def test_checked_in_baseline_lists_every_package(self):
        path = Path(__file__).resolve().parent / "baseline.json"
        maxima = json.loads(path.read_text())["max_sites"]
        self.assertEqual(set(maxima), set(crate_names()))
        for value in maxima.values():
            self.assertIsInstance(value, int)
            self.assertGreaterEqual(value, 0)


if __name__ == "__main__":
    unittest.main()
