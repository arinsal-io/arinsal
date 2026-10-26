use arinsal_etf::OwnedTerm;
use arinsal_term::{HeapBinaryWriter, ProcessHeap, to_owned};
use similar_asserts::assert_eq;

#[test]
fn every_small_binary_split_preserves_bytes_and_gc_state() {
    for len in 0..=64 {
        let bytes = (0..len).map(|i| (i * 137 + 23) as u8).collect::<Vec<_>>();
        for split in 0..=len {
            let mut heap = ProcessHeap::with_words(256);
            let mut writer = HeapBinaryWriter::new(&mut heap, len).unwrap();
            writer.write(&mut heap, &bytes[..split]).unwrap();
            for byte in &bytes[split..] {
                writer.write(&mut heap, &[*byte]).unwrap();
            }
            let result = writer.finish(&mut heap).unwrap();
            assert!(heap.gc_enabled);
            assert_eq!(to_owned(result).unwrap(), OwnedTerm::Binary(bytes.clone()));
        }
    }
}

#[test]
fn cancel_partial_binary_releases_the_reservation() {
    let mut heap = ProcessHeap::with_words(256);
    let available = heap.words_left();
    let mut writer = HeapBinaryWriter::new(&mut heap, 64).unwrap();
    writer.write(&mut heap, &[255; 13]).unwrap();
    writer.cancel(&mut heap);
    assert!(heap.gc_enabled);
    assert_eq!(heap.words_left(), available);
}
