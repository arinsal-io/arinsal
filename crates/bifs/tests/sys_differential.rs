mod support;

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm as O;
use support::{call, equivalent};

#[test]
fn os_pid_and_getenv_bifs_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping os BIF differential test");
        return;
    };
    for (name, args) in [
        ("getpid", vec![]),
        ("perf_counter", vec![]),
        ("getenv", vec![O::charlist("HOME")]),
    ] {
        let expected = reference.call("os", name, &args);
        let actual = call("os", name, &args);
        if name == "getpid" || name == "perf_counter" {
            assert!(matches!(actual, CallResult::Ok(_)), "os:{name}: {actual:?}");
            assert!(
                matches!(expected, CallResult::Ok(_)),
                "reference os:{name}: {expected:?}"
            );
        } else {
            assert!(
                equivalent(&actual, &expected),
                "os:{name}: {actual:?} != {expected:?}"
            );
            assert_eq!(actual, expected, "os:{name}");
        }
    }
    let invalid = [O::Int(2)];
    let expected = reference.call("os", "getenv", &invalid);
    let actual = call("os", "getenv", &invalid);
    assert!(equivalent(&actual, &expected), "os:getenv error class");
}
