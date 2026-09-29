//! ERTS allocator registry and per-instance defaults.

use crate::alloc_util::{AllocUtilOptions, Strategy};

/// Default options for one OTP allocator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocatorSpec {
    /// Public allocator name used by `system_info/1`.
    pub name: &'static str,
    /// Prefix used by allocator block records.
    pub prefix: &'static str,
    /// Whether allocation is enabled by default.
    pub enabled: bool,
    /// Whether the allocator owns scheduler-local instances.
    pub thread_specific: bool,
    /// Strategy used by allocator operations.
    pub strategy: Strategy,
    /// Strategy atom exposed through the `as` option.
    pub strategy_name: &'static str,
    /// Whether allocation origin tags are enabled.
    pub atags: bool,
    /// Allocator carrier settings.
    pub options: AllocUtilOptions,
}

/// Names returned by OTP's `system_info(alloc_util_allocators)`.
pub const ALLOC_UTIL_ALLOCATORS: &[&str] = &[
    "temp_alloc",
    "sl_alloc",
    "std_alloc",
    "ll_alloc",
    "eheap_alloc",
    "ets_alloc",
    "fix_alloc",
    "literal_alloc",
    "binary_alloc",
    "driver_alloc",
];

/// Return the OTP 29.1.1 allocator defaults for the configured scheduler count.
pub fn defaults(schedulers: usize) -> Vec<AllocatorSpec> {
    let schedulers = schedulers.max(1);
    let mbc = 128 * 1024 / schedulers.min(4);
    let lbc = 5 * 1024 * 1024;
    let sbc = 1024 * 1024 / schedulers.min(4);
    let make = |name, prefix, strategy, strategy_name, atags, mbcs| {
        let options = AllocUtilOptions {
            mmbcs: mbcs,
            lmbcs: lbc,
            smbcs: sbc,
            ..AllocUtilOptions::default()
        };
        AllocatorSpec {
            name,
            prefix,
            enabled: true,
            thread_specific: true,
            strategy,
            strategy_name,
            atags,
            options,
        }
    };

    let mut temp = make(
        "temp_alloc",
        "temp_",
        Strategy::Afit,
        "af",
        false,
        128 * 1024,
    );
    temp.options.rsbcst = 90;
    temp.options.rmbcmt = 100;
    temp.options.lmbcs = 10 * 1024 * 1024;
    temp.options.smbcs = 1024 * 1024;

    let mut sl = make(
        "sl_alloc",
        "sl_",
        Strategy::AddressOrderBestFit,
        "aoffcbf",
        false,
        mbc,
    );
    sl.options.rsbcst = 80;
    sl.options.rmbcmt = 50;

    let mut std = make(
        "std_alloc",
        "std_",
        Strategy::BestFit,
        "aoffcbf",
        false,
        mbc,
    );
    std.options.rsbcst = 20;

    let mut ll = make(
        "ll_alloc",
        "ll_",
        Strategy::BestFit,
        "aoffcbf",
        false,
        2 * 1024 * 1024 / schedulers.min(4),
    );
    ll.options.sbct = usize::MAX;
    ll.options.asbcst = 0;
    ll.options.rsbcst = 0;
    ll.options.rsbcmt = 0;
    ll.options.rmbcmt = 0;
    ll.options.mmsbc = 0;

    let mut eheap = make(
        "eheap_alloc",
        "eheap_",
        Strategy::GoodFit,
        "aoffcbf",
        false,
        512 * 1024 / schedulers.min(4),
    );
    eheap.options.rsbcst = 50;

    let mut ets = make(
        "ets_alloc",
        "ets_",
        Strategy::BestFit,
        "aoffcbf",
        false,
        mbc,
    );
    ets.options.rsbcst = 20;

    let mut fix = make(
        "fix_alloc",
        "fix_",
        Strategy::BestFit,
        "aoffcbf",
        false,
        mbc,
    );
    fix.options.rsbcst = 20;

    let mut literal = make(
        "literal_alloc",
        "literal_",
        Strategy::AddressOrderBestFit,
        "aobf",
        false,
        1024 * 1024,
    );
    literal.thread_specific = false;
    literal.options.sbct = usize::MAX;
    literal.options.asbcst = 0;
    literal.options.rsbcst = 0;
    literal.options.rsbcmt = 0;
    literal.options.rmbcmt = 0;
    literal.options.mmsbc = 0;
    literal.options.lmbcs = 10 * 1024 * 1024;
    literal.options.smbcs = 1024 * 1024;

    let mut binary = make(
        "binary_alloc",
        "binary_",
        Strategy::BestFit,
        "aoffcbf",
        true,
        mbc,
    );
    binary.options.rsbcst = 20;
    binary.options.rmbcmt = 50;

    let mut driver = make(
        "driver_alloc",
        "driver_",
        Strategy::BestFit,
        "aoffcbf",
        true,
        mbc,
    );
    driver.options.rsbcst = 20;
    driver.options.rmbcmt = 50;

    vec![temp, sl, std, ll, eheap, ets, fix, literal, binary, driver]
}

/// Look up one allocator's default specification.
pub fn allocator(name: &str, schedulers: usize) -> Option<AllocatorSpec> {
    defaults(schedulers)
        .into_iter()
        .find(|spec| spec.name == name)
}

/// Number of instances including the shared global instance at index zero.
pub fn instance_count(spec: &AllocatorSpec, schedulers: usize, dirty_instances: usize) -> usize {
    if spec.thread_specific {
        1 + schedulers.max(1) + dirty_instances
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::{ALLOC_UTIL_ALLOCATORS, defaults, instance_count};
    use std::process::Command;

    #[test]
    fn alloc_a4_instance_counts_match_otp() {
        let Ok(output) = Command::new("erl")
            .args([
                "-noshell",
                "-eval",
                "As=erlang:system_info(alloc_util_allocators), io:format(\"~s\", [string:join([atom_to_list(A) ++ \":\" ++ integer_to_list(length([I || I={instance,_,_} <- erlang:system_info({allocator,A})])) || A <- As], \",\")]), halt().",
            ])
            .output()
        else {
            eprintln!("skipping alloc_a4_instance_counts_match_otp: erl is unavailable");
            return;
        };
        assert!(output.status.success());
        let reference = String::from_utf8(output.stdout).unwrap();
        let schedulers = Command::new("erl")
            .args([
                "-noshell",
                "-eval",
                "io:format(\"~p\",[erlang:system_info(schedulers)]),halt().",
            ])
            .output()
            .unwrap();
        let schedulers: usize = String::from_utf8(schedulers.stdout)
            .unwrap()
            .parse()
            .unwrap();
        let expected = defaults(schedulers)
            .iter()
            .map(|spec| format!("{}:{}", spec.name, instance_count(spec, schedulers, 0)))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(reference, expected);
        assert_eq!(
            ALLOC_UTIL_ALLOCATORS,
            defaults(schedulers)
                .iter()
                .map(|spec| spec.name)
                .collect::<Vec<_>>()
        );
    }
}
