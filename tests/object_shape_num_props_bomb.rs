//! Acceptance test for the `MAX_OBJECT_SHAPE_NUM_PROPS` cap.
//!
//! Amplification: `parser::HbcFile::object_shape_get` returns an
//! attacker-controlled `num_props: u32` to `decompile::optimize::
//! resolve_buffers`, where it drives `Vec::with_capacity(num_props as
//! usize)` and `for i in 0..num_props` loops. At `num_props = 1 << 28`
//! that's a multi-GB allocation request + ~268M iterations — DoS via
//! amplification.
//!
//! Cap: a per-shape consumer-side cap at the two `Vec::with_capacity`
//! sites in `optimize::resolve_buffers` rejects
//! `num_props > MAX_OBJECT_SHAPE_NUM_PROPS` (default 65 536), emits a
//! typed `HermesFinding::ObjectShapeNumPropsExceeded`, installs an
//! unresolved-buffer placeholder, and continues (lenient policy).
//!
//! The fixture below carries one shape entry with `num_props = 1 <<
//! 20` (~1M, well above the 65 536 cap). The parser passes the value
//! through unchanged — the cap fires at the decompile consumer, not
//! at parse — so this test asserts the parser observation only. The
//! consumer-side cap behavior is locked by unit tests in
//! `decompile::optimize::unresolved_buffer_tests`:
//! `new_object_with_buffer_v84_v96_num_props_cap_fires`,
//! `new_object_with_buffer_v97_num_props_cap_fires`, and
//! `new_object_with_buffer_at_cap_does_not_fire`.

use std::fs;
use std::time::Instant;

use droidsaw_hermes::parser::HbcFile;

const FIXTURE_PATH: &str =
    "tests/fixtures/adversarial/object_shape_num_props_bomb/shape_table_bomb_v97.hbc";

const BOMB_NUM_PROPS: u32 = 1 << 20;

/// Build a 136-byte v97 HBC carrying one ObjShapeTable entry whose
/// `num_props = 1 << 20`. Layout per `header::parse_v97_to_v98_early`
/// + `parser::parse_inner`'s `section!` walk: Header(128) + zero-sized
///   FunctionHeaders/StringKinds/IdentifierHashes/SmallStringTable/
///   OverflowStringTable/StringStorage/ArrayBuffer/ObjKeyBuffer +
///   ObjShapeTable(8) = 136 bytes total.
fn build_shape_table_bomb_v97() -> Vec<u8> {
    let mut buf = vec![0u8; 136];
    // Magic + version 97 (in-range per `MIN_SUPPORTED_VERSION`).
    buf[0..8].copy_from_slice(&0x1F1903C103BC1FC6u64.to_le_bytes());
    buf[8..12].copy_from_slice(&97u32.to_le_bytes());
    // file_length matches buf.len() so the file-length cross-validation
    // Finding does not fire spuriously.
    buf[32..36].copy_from_slice(&136u32.to_le_bytes());
    // obj_shape_table_count @88 = 1 entry.
    buf[88..92].copy_from_slice(&1u32.to_le_bytes());
    // ObjShapeTable @128: one 8-byte entry (key_buffer_offset, num_props).
    buf[128..132].copy_from_slice(&0u32.to_le_bytes());
    buf[132..136].copy_from_slice(&BOMB_NUM_PROPS.to_le_bytes());
    buf
}

#[test]
fn fixture_bytes_match_disk() {
    let on_disk = fs::read(FIXTURE_PATH)
        .expect("fixture must be checked in — run regen_object_shape_num_props_bomb_fixture");
    assert_eq!(on_disk, build_shape_table_bomb_v97());
}

#[test]
fn parse_succeeds_passes_bomb_through() {
    let bytes = build_shape_table_bomb_v97();
    // Parse must complete in well under 100 ms — the cap fires at
    // the decompile consumer; parse alone reads only the 8-byte
    // shape entry and does no per-num_props work.
    let start = Instant::now();
    let hbc = HbcFile::parse(&bytes, None).expect("v97 header parses cleanly");
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_millis() < 100,
        "parse took {elapsed:?}, expected < 100ms (cap fires before allocation)"
    );

    assert_eq!(hbc.version, 97);
    assert_eq!(hbc.shape_table_count(), 1);

    // The parser passes attacker-controlled `num_props` through
    // unchanged; the cap is enforced at the decompile consumer.
    let shape = hbc
        .object_shape_get(0)
        .expect("shape[0] is in-bounds in the fixture (count=1)");
    assert_eq!(shape.num_props, BOMB_NUM_PROPS);
    assert_eq!(shape.key_buffer_offset, 0);
}

#[test]
fn fixture_loads_and_parses_under_100ms() {
    let bytes = fs::read(FIXTURE_PATH).expect("fixture must be checked in");
    let start = Instant::now();
    let hbc = HbcFile::parse(&bytes, None).expect("v97 header parses cleanly");
    let elapsed = start.elapsed();
    assert!(elapsed.as_millis() < 100, "parse took {elapsed:?}");
    assert_eq!(hbc.shape_table_count(), 1);
    assert_eq!(
        hbc.object_shape_get(0)
            .expect("shape[0] is in-bounds in the fixture (count=1)")
            .num_props,
        BOMB_NUM_PROPS
    );
}

/// Regenerate the on-disk fixture. `#[ignore]` in CI; run manually
/// with `cargo test --test object_shape_num_props_bomb regen_ --
/// --ignored --nocapture`.
#[test]
#[ignore = "regen helper — run manually with --ignored after layout changes"]
fn regen_object_shape_num_props_bomb_fixture() {
    let bytes = build_shape_table_bomb_v97();
    let path = std::path::Path::new(FIXTURE_PATH);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, &bytes).unwrap();
    println!("wrote {} bytes to {FIXTURE_PATH}", bytes.len());
}
