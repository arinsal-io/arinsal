//! Safe x86 feature predicates corresponding to BeamAsm `hasCpuFeature` checks.
//!
//! Port of `BeamAssemblerCommon::hasCpuFeature` in `erts/emulator/beam/jit/beam_jit_main.cpp`
//! (OTP-29.1.1), which reads the initialized asmjit `CpuInfo` feature bitset. Rust's safe
//! `is_x86_feature_detected!` predicates include the OS state checks required by AVX.

/// Returns whether the CPU supports BMI1 (`tzcnt`, `andn`).
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn has_bmi1() -> bool {
    std::arch::is_x86_feature_detected!("bmi1")
}

/// Returns `false` because this target is not x86.
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn has_bmi1() -> bool {
    false
}

/// Returns whether the CPU supports BMI2.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn has_bmi2() -> bool {
    std::arch::is_x86_feature_detected!("bmi2")
}

/// Returns `false` because this target is not x86.
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn has_bmi2() -> bool {
    false
}

/// Returns whether the CPU supports LZCNT.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn has_lzcnt() -> bool {
    std::arch::is_x86_feature_detected!("lzcnt")
}

/// Returns `false` because this target is not x86.
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn has_lzcnt() -> bool {
    false
}

/// Returns whether the CPU supports POPCNT.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn has_popcnt() -> bool {
    std::arch::is_x86_feature_detected!("popcnt")
}

/// Returns `false` because this target is not x86.
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn has_popcnt() -> bool {
    false
}

/// Returns whether the CPU and OS support AVX.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn has_avx() -> bool {
    std::arch::is_x86_feature_detected!("avx")
}

/// Returns `false` because this target is not x86.
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn has_avx() -> bool {
    false
}

/// Returns whether the CPU and OS support AVX2.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn has_avx2() -> bool {
    std::arch::is_x86_feature_detected!("avx2")
}

/// Returns `false` because this target is not x86.
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn has_avx2() -> bool {
    false
}

/// Returns whether the CPU and OS support AVX-512 Foundation.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn has_avx512f() -> bool {
    std::arch::is_x86_feature_detected!("avx512f")
}

/// Returns `false` because this target is not x86.
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn has_avx512f() -> bool {
    false
}

/// Returns whether the CPU and OS support AVX-512 Vector Length extensions.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn has_avx512vl() -> bool {
    std::arch::is_x86_feature_detected!("avx512vl")
}

/// Returns `false` because this target is not x86.
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn has_avx512vl() -> bool {
    false
}

/// Returns whether the CPU supports MOVBE.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn has_movbe() -> bool {
    std::arch::is_x86_feature_detected!("movbe")
}

/// Returns `false` because this target is not x86.
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn has_movbe() -> bool {
    false
}
