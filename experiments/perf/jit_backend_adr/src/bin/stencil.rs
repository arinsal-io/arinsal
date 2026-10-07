//! AArch64 Rust-to-object copy-and-patch feasibility probe.

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
mod mac {
    use object::{Object, ObjectSection, ObjectSymbol};
    use std::ffi::c_void;
    use std::hint::black_box;
    use std::time::Instant;

    unsafe extern "C" {
        fn sys_icache_invalidate(start: *mut c_void, len: usize);
    }

    fn median(mut values: Vec<f64>) -> f64 {
        values.sort_by(f64::total_cmp);
        values[values.len() / 2]
    }

    fn patch_add(bytes: &mut [u8], replacement: u16) -> bool {
        let (words, _) = bytes.as_chunks_mut::<4>();
        for word in words {
            let mut encoded = u32::from_le_bytes(*word);
            let opcode = encoded & 0xff80_0000;
            let immediate = (encoded >> 5) & 0xffff;
            if (opcode == 0xd280_0000 || opcode == 0x5280_0000) && immediate == 0x12ab {
                encoded = (encoded & !(0xffff << 5)) | (u32::from(replacement) << 5);
                word.copy_from_slice(&encoded.to_le_bytes());
                return true;
            }
        }
        false
    }

    pub fn run() {
        let obj =
            object::File::parse(include_bytes!(concat!(env!("OUT_DIR"), "/stencil.o")).as_slice())
                .unwrap();
        let mut add = None;
        let mut helper_relocs = 0;
        for symbol in obj.symbols() {
            let Ok(raw_name) = symbol.name() else {
                continue;
            };
            let name = raw_name.trim_start_matches('_');
            if name != "stencil_add" && name != "stencil_helper" {
                continue;
            }
            let section = obj
                .section_by_index(symbol.section_index().unwrap())
                .unwrap();
            let offset = (symbol.address() - section.address()) as usize;
            let end_address = obj
                .symbols()
                .filter(|other| {
                    other.section_index() == symbol.section_index()
                        && other.address() > symbol.address()
                })
                .map(|other| other.address())
                .min()
                .unwrap_or(section.address() + section.data().unwrap().len() as u64);
            let size = if symbol.size() == 0 {
                (end_address - symbol.address()) as usize
            } else {
                symbol.size() as usize
            };
            if name == "stencil_add" {
                add = Some(section.data().unwrap()[offset..offset + size].to_vec());
            } else {
                helper_relocs = section
                    .relocations()
                    .filter(|(at, _)| *at >= offset as u64 && *at < (offset + size) as u64)
                    .count();
            }
        }
        let source = add.expect("stencil_add symbol missing");
        assert!(helper_relocs > 0, "external helper relocation missing");
        let mut patched = source.clone();
        assert!(
            patch_add(&mut patched, 7),
            "rustc no longer emits expected MOVZ stencil"
        );
        let mut samples = Vec::new();
        for _ in 0..9 {
            let start = Instant::now();
            for _ in 0..1000 {
                let mut code = source.clone();
                assert!(patch_add(&mut code, 7));
                black_box(code);
            }
            samples.push(start.elapsed().as_nanos() as f64 / 1000.0);
        }
        // SAFETY: mmap returns a private MAP_JIT region whose lifetime spans the native call.
        let memory = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_JIT,
                -1,
                0,
            )
        };
        assert_ne!(memory, libc::MAP_FAILED);
        // SAFETY: This thread alone writes the mapping before execution, then restores RX mode.
        unsafe {
            libc::pthread_jit_write_protect_np(0);
            std::ptr::copy_nonoverlapping(patched.as_ptr(), memory.cast::<u8>(), patched.len());
            libc::pthread_jit_write_protect_np(1);
            sys_icache_invalidate(memory, patched.len());
        }
        // SAFETY: The copied Rust function has the declared platform C ABI and no relocations.
        let f: extern "C" fn(i64) -> i64 = unsafe { std::mem::transmute(memory) };
        let result = f(5);
        assert_eq!(result, 12);
        // SAFETY: The mapping has no active native callers after the return above.
        unsafe {
            libc::munmap(memory, 4096);
        }
        println!(
            "stencil_bytes={} helper_relocations={} copy_patch_1000_median_us={:.1} patched_result={result}",
            source.len(),
            helper_relocs,
            median(samples)
        );
    }
}

fn main() {
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    mac::run();
    #[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
    println!("The executable stencil probe requires macOS AArch64.");
}

#[cfg(all(test, target_arch = "aarch64", target_os = "macos"))]
mod tests {
    #[test]
    fn rust_object_stencil_patches_and_executes() {
        super::mac::run();
    }
}
