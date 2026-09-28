use flate2::{
    Compression,
    write::{GzEncoder, ZlibEncoder},
};
use std::{fs, io::Write};

mod support;

fn lists() -> Option<Vec<u8>> {
    let path = support::otp_root()?.join("lib/stdlib-8.1/ebin/lists.beam");
    match fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            eprintln!("OTP 29 lists.beam absent; skipping");
            None
        }
    }
}

#[test]
fn gzip_container_preserves_contents() {
    let Some(bytes) = lists() else { return };
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&bytes).unwrap();
    let compressed = encoder.finish().unwrap();
    let normal = arinsal_beam::parse(&bytes).unwrap();
    let decoded = arinsal_beam::parse(&compressed).unwrap();
    assert_eq!(decoded.module, normal.module);
    assert_eq!(
        decoded.code.instructions.len(),
        normal.code.instructions.len()
    );
}

#[test]
fn compressed_literals_match_otp29_uncompressed_literals() {
    let Some(bytes) = lists() else { return };
    let old = arinsal_beam::parse(&bytes).unwrap();
    let mut rewritten = b"FOR1\0\0\0\0BEAM".to_vec();
    let mut pos = 12;
    while pos < bytes.len() {
        let id = &bytes[pos..pos + 4];
        let size = u32::from_be_bytes(bytes[pos + 4..pos + 8].try_into().unwrap()) as usize;
        let data = &bytes[pos + 8..pos + 8 + size];
        rewritten.extend_from_slice(id);
        if id == b"LitT" {
            assert_eq!(&data[..4], &[0, 0, 0, 0]);
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&data[4..]).unwrap();
            let compressed = encoder.finish().unwrap();
            let mut payload = (data.len() as u32 - 4).to_be_bytes().to_vec();
            payload.extend(compressed);
            rewritten.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            rewritten.extend_from_slice(&payload);
            rewritten.resize(rewritten.len() + (4 - payload.len() % 4) % 4, 0);
        } else {
            rewritten.extend_from_slice(&(size as u32).to_be_bytes());
            rewritten.extend_from_slice(data);
            rewritten.resize(rewritten.len() + (4 - size % 4) % 4, 0);
        }
        pos += 8 + size + (4 - size % 4) % 4;
    }
    let form_size = (rewritten.len() - 8) as u32;
    rewritten[4..8].copy_from_slice(&form_size.to_be_bytes());
    let new = arinsal_beam::parse(&rewritten).unwrap();
    assert_eq!(new.literals.len(), old.literals.len());
    for (new, old) in new.literals.iter().zip(old.literals.iter()) {
        assert_eq!(new.0, old.0);
        assert_eq!(new.0[0], 131);
    }
}

#[test]
fn legacy_atom_chunk_decodes_latin1() {
    let Some(bytes) = lists() else { return };
    let normal = arinsal_beam::parse(&bytes).unwrap();
    let mut atom_data = (normal.atoms.len() as u32).to_be_bytes().to_vec();
    for (index, atom) in normal.atoms.iter().enumerate() {
        let text = if index == 0 { "lïsts" } else { atom };
        let latin1: Vec<u8> = text
            .chars()
            .map(|c| u8::try_from(c as u32).unwrap())
            .collect();
        atom_data.push(u8::try_from(latin1.len()).unwrap());
        atom_data.extend(latin1);
    }
    let mut rewritten = b"FOR1\0\0\0\0BEAM".to_vec();
    let mut pos = 12;
    while pos < bytes.len() {
        let id = &bytes[pos..pos + 4];
        let size = u32::from_be_bytes(bytes[pos + 4..pos + 8].try_into().unwrap()) as usize;
        let data = &bytes[pos + 8..pos + 8 + size];
        let (id, data) = if id == b"AtU8" {
            (b"Atom".as_slice(), atom_data.as_slice())
        } else {
            (id, data)
        };
        rewritten.extend(id);
        rewritten.extend((data.len() as u32).to_be_bytes());
        rewritten.extend(data);
        rewritten.resize(rewritten.len() + (4 - data.len() % 4) % 4, 0);
        pos += 8 + size + (4 - size % 4) % 4;
    }
    let form_size = (rewritten.len() - 8) as u32;
    rewritten[4..8].copy_from_slice(&form_size.to_be_bytes());
    let beam = arinsal_beam::parse(&rewritten).unwrap();
    assert_eq!(beam.module, "lïsts");
    assert_eq!(beam.atoms.len(), normal.atoms.len());
    assert_eq!(beam.code.instructions.len(), normal.code.instructions.len());
}
