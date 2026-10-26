use std::hint::black_box;
use std::path::Path;
use std::time::Instant;

use arinsal_bifs::{Ctx, ProcessHeapHandle};
use arinsal_nif::{LoadInfo, load_nif};
use arinsal_term::{ProcessHeap, Term, TermBuilder, VecHeap, global_atoms};

fn main() {
    let path = std::env::args().nth(1).expect("NIF path");
    let module = std::env::args().nth(2).unwrap_or_else(|| "nb".into());
    let mut heap = VecHeap::new();
    let info = if module == "crypto" {
        let mut builder = TermBuilder::new(&mut heap);
        let binary = builder.binary(path.as_bytes()).unwrap();
        let false_atom = Term::atom(global_atoms().get("false").unwrap());
        builder
            .tuple(&[Term::small(302).unwrap(), binary, false_atom])
            .unwrap()
    } else {
        Term::NIL
    };
    let library = load_nif(
        Path::new(&path),
        LoadInfo {
            module: &module,
            term: info,
        },
    )
    .unwrap();
    let mut output_heap = ProcessHeap::with_words(4096);
    println!("loaded {module}: {} functions", library.functions().len());
    if module == "nb" {
        let args = [Term::small(2).unwrap(), Term::small(3).unwrap()];
        for (name, args) in [("noop", &args[..1]), ("add", &args[..])] {
            let mut state = arinsal_bifs::BifState::default();
            let mut ctx = Ctx::with_allocator(ProcessHeapHandle(&mut output_heap), &mut state);
            let result = library
                .lookup(name, args.len())
                .unwrap()
                .call(&mut ctx, args)
                .unwrap();
            println!("{name}: {}", result.as_small().unwrap());
        }
        let mut state = arinsal_bifs::BifState::default();
        let mut ctx = Ctx::with_allocator(ProcessHeapHandle(&mut output_heap), &mut state);
        for (name, args) in [("noop", &args[..1]), ("add", &args[..])] {
            let callback = library.lookup(name, args.len()).unwrap();
            let count = 5_000_000;
            let start = Instant::now();
            for _ in 0..count {
                black_box(callback.call(black_box(&mut ctx), black_box(args)).unwrap());
            }
            println!(
                "{name} adapter: {:.1} ns/call",
                start.elapsed().as_nanos() as f64 / count as f64
            );
        }
    }
    if module == "crypto" {
        let sha = Term::atom(global_atoms().intern("sha256").unwrap());
        let hmac = Term::atom(global_atoms().intern("hmac").unwrap());
        let aes = Term::atom(global_atoms().intern("aes_128_ctr").unwrap());
        let yes = Term::atom(global_atoms().get("true").unwrap());
        let mut builder = TermBuilder::new(&mut heap);
        let abc = builder.binary(b"abc").unwrap();
        let key = builder.binary(&[0; 16]).unwrap();
        let iv = builder.binary(&[0; 16]).unwrap();
        let hmac_key = builder.binary(b"key").unwrap();
        let calls = [
            ("hash_nif", vec![sha, abc]),
            ("mac_nif", vec![hmac, sha, hmac_key, abc]),
            ("strong_rand_bytes_nif", vec![Term::small(32).unwrap()]),
            ("ng_crypto_one_time_nif", vec![aes, key, iv, abc, yes]),
        ];
        for (name, args) in calls {
            let mut state = arinsal_bifs::BifState::default();
            let mut ctx = Ctx::with_allocator(ProcessHeapHandle(&mut output_heap), &mut state);
            let result = library
                .lookup(name, args.len())
                .unwrap()
                .call(&mut ctx, &args)
                .unwrap();
            // SAFETY: heap remains live and stable while printing the result.
            let view = unsafe { result.binary_ref() }.unwrap();
            let data = &view.bytes()[view.start_bit() / 8..][..view.bit_len() / 8];
            if name == "strong_rand_bytes_nif" {
                println!("{name}: len={}", data.len());
            } else {
                println!(
                    "{name}: {}",
                    data.iter().map(|b| format!("{b:02x}")).collect::<String>()
                );
            }
        }
    }
}
