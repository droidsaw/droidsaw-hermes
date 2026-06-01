//! Negative properties for `HbcFile::parse`: a malformed HBC header must
//! surface a typed `HermesError`, never `Ok` of a wrong IR. HBC carries no
//! parser-validated checksum (`sourceHash` / `file_length` are informational),
//! so the generators mutate header counts directly with no reseal. hermes is
//! strict by design — `parse_inner` cross-validates the counts up front — so
//! these pin the typed-Err contract over a symbolic range (the dedicated
//! `overflow_string_oor` / `bound_count_amplification` fixtures cover single
//! points; these generalize them).

use droidsaw_hermes::error::HermesError;
use droidsaw_hermes::parser::HbcFile;
use proptest::prelude::*;

const HBC_MAGIC: u64 = 0x1F19_03C1_03BC_1FC6;

// Minimal v96 HBC header, 132 bytes (> the 128-byte upfront gate), all counts
// zero; callers set the fields under test. Header offsets per `src/header.rs`:
//   magic@0, version@8, sourceHash@12 (unvalidated), file_length@32 (info),
//   function_count@40, string_kind_count@44, identifier_count@48,
//   string_count@52, overflow_string_count@56, string_storage_size@60, …
fn v96_header() -> Vec<u8> {
    let mut buf = vec![0u8; 132];
    buf[0..8].copy_from_slice(&HBC_MAGIC.to_le_bytes());
    buf[8..12].copy_from_slice(&96u32.to_le_bytes());
    buf
}

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

proptest! {
    /// `overflow_string_count > string_count` is structurally impossible (the
    /// overflow entries are a sub-pool of the string pool), so `parse_inner`
    /// fails closed with a typed `OverflowStringCountExceedsStringCount` — never
    /// `Ok` of a corrupt string table.
    #[test]
    fn overflow_string_count_gt_total_is_typed_err(
        total in 0u32..1000,
        extra in 1u32..1000,
    ) {
        let mut buf = v96_header();
        put_u32(&mut buf, 52, total);                       // string_count
        put_u32(&mut buf, 56, total.saturating_add(extra)); // overflow_string_count > total
        let r = HbcFile::parse(&buf, None);
        prop_assert!(
            matches!(&r, Err(HermesError::OverflowStringCountExceedsStringCount { .. })),
            "expected OverflowStringCountExceedsStringCount, got {}",
            r.as_ref().map_or_else(|e| format!("{e:?}"), |_| "Ok(parsed)".into()),
        );
    }

    /// A `string_count` whose table (`count * 4`) exceeds the input length is
    /// caught by the `bound_count` guard → typed `BoundCountExceeded`, never an
    /// over-allocation or a silently-truncated table. The buffer is 132 bytes,
    /// so the guard's max is `132 / 4 = 33` and it fires on `got > 33`; the
    /// range therefore starts at `34` (`34 * 4 = 136 > 132`) — at exactly 33 the
    /// bound_count guard passes and a later `SectionExceedsBounds` fires instead.
    /// `overflow_string_count` stays 0 (≤ count) so the overflow cross-check
    /// passes and the bound_count guard is the gate hit.
    #[test]
    fn oversized_string_count_is_bound_count_err(count in 34u32..1_000_000) {
        let mut buf = v96_header();
        put_u32(&mut buf, 52, count); // string_count (oversized)
        let r = HbcFile::parse(&buf, None);
        prop_assert!(
            matches!(&r, Err(HermesError::BoundCountExceeded(_))),
            "expected BoundCountExceeded, got {}",
            r.as_ref().map_or_else(|e| format!("{e:?}"), |_| "Ok(parsed)".into()),
        );
    }
}
