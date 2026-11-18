//! CPU feature predicates use Rust's safe standard-library detection wrappers.

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[test]
fn predicates_match_std_arch_detection() {
    use arinsal_x64::enc::cpu;
    use similar_asserts::assert_eq;

    assert_eq!(cpu::has_bmi1(), std::arch::is_x86_feature_detected!("bmi1"));
    assert_eq!(cpu::has_bmi2(), std::arch::is_x86_feature_detected!("bmi2"));
    assert_eq!(
        cpu::has_lzcnt(),
        std::arch::is_x86_feature_detected!("lzcnt")
    );
    assert_eq!(
        cpu::has_popcnt(),
        std::arch::is_x86_feature_detected!("popcnt")
    );
    assert_eq!(cpu::has_avx(), std::arch::is_x86_feature_detected!("avx"));
    assert_eq!(cpu::has_avx2(), std::arch::is_x86_feature_detected!("avx2"));
    assert_eq!(
        cpu::has_movbe(),
        std::arch::is_x86_feature_detected!("movbe")
    );
}
