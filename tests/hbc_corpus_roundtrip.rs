//! Corpus-scale `parse → emit_hbc → parse` round-trip validation for
//! v96 HBC files. Env-gated: set `DROIDSAW_HERMES_V96_CORPUS` to a
//! directory of `.hbc` files; the test iterates every sample and
//! asserts `HbcFileEquiv<V96>` holds across round-trip. Skips cleanly
//! if the env var isn't set (fresh clones have no staged corpus).
//!
//! `HbcFileEquiv<V96>` is the emit specification — this test is the
//! corpus-scale instantiation of it. Structural equivalence is the v1
//! gate ("self-referential involution"); byte-identity emerges as a
//! deterministic consequence for inputs without garbage in parser-
//! ignored header fields.
//!
//! debug_info is PASSTHROUGH on emit (HBC debug_info is line-number +
//! scope-chain metadata, not a dangling-pointer-vector like DEX).
//! Corpus samples with non-zero `debug_filename_count` round-trip with
//! debug info preserved.
//!
//! ## Staging the corpus
//!
//! The test iterates every `*.hbc` file under the path given by
//! `$DROIDSAW_HERMES_V96_CORPUS` and asserts `HbcFileEquiv<V96>` plus
//! byte-identical round-trip on each v96 sample; non-v96 samples skip
//! cleanly. Stage your own corpus — this repo does not ship production
//! bundles. Typical extraction from a React Native APK:
//!
//! ```bash
//! # For each APK you want to include:
//! unzip -p /path/to/your-app.apk assets/index.android.bundle \
//!     > /path/to/your-corpus-dir/your-app.hbc
//!
//! DROIDSAW_HERMES_V96_CORPUS=/path/to/your-corpus-dir \
//!     cargo test -p droidsaw-hermes --release --test hbc_corpus_roundtrip -- --nocapture
//! ```

use droidsaw_hermes::emit::{emit_hbc, emit_hbc_v84, emit_hbc_v98, emit_hbc_v99};
use droidsaw_hermes::parser::{HbcFile, HbcFileEquiv, V84, V96, V98, V99};
use std::fs;
use std::path::PathBuf;

const CORPUS_ENV: &str = "DROIDSAW_HERMES_V96_CORPUS";

fn resolve_corpus_dir() -> Option<PathBuf> {
    let raw = std::env::var(CORPUS_ENV).ok()?;
    let path = PathBuf::from(raw);
    if path.is_dir() { Some(path) } else { None }
}

/// Iterate `*.hbc` entries in `dir` sorted by name.
fn hbc_samples(dir: &PathBuf) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .and_then(|s| s.to_str())
                    .map(|s| s.eq_ignore_ascii_case("hbc"))
                    .unwrap_or(false)
        })
        .collect();
    out.sort();
    out
}

#[test]
fn corpus_v96_roundtrip_structural_equivalence() {
    let Some(dir) = resolve_corpus_dir() else {
        eprintln!(
            "SKIP: {CORPUS_ENV} not set or not a directory; staging instructions in test file header"
        );
        return;
    };

    let samples = hbc_samples(&dir);
    if samples.is_empty() {
        eprintln!("SKIP: no .hbc files under {}", dir.display());
        return;
    }

    let mut v84_checked = 0u32;
    let mut v84_equiv_passed = 0u32;
    let mut v84_byte_identical = 0u32;
    let mut v96_checked = 0u32;
    let mut v96_equiv_passed = 0u32;
    let mut v96_byte_identical = 0u32;
    let mut v98_checked = 0u32;
    let mut v98_equiv_passed = 0u32;
    let mut v98_byte_identical = 0u32;
    let mut v99_checked = 0u32;
    let mut v99_equiv_passed = 0u32;
    let mut v99_byte_identical = 0u32;
    let mut unsupported_version_skipped = 0u32;
    let mut parse_failed = 0u32;

    for path in &samples {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("<?>");
        let Ok(bytes) = fs::read(path) else {
            eprintln!("ERR: read failed for {name}");
            continue;
        };

        let Ok(hbc1) = HbcFile::parse(&bytes, None) else {
            eprintln!("PARSE-FAIL: {name}");
            parse_failed += 1;
            continue;
        };

        if HbcFileEquiv::<V84>::new(&hbc1).is_some() {
            v84_checked += 1;
            check_v84_roundtrip(name, &bytes, &hbc1, &mut v84_equiv_passed, &mut v84_byte_identical);
        } else if HbcFileEquiv::<V96>::new(&hbc1).is_some() {
            v96_checked += 1;
            check_v96_roundtrip(name, &bytes, &hbc1, &mut v96_equiv_passed, &mut v96_byte_identical);
        } else if HbcFileEquiv::<V98>::new(&hbc1).is_some() {
            v98_checked += 1;
            check_v98_roundtrip(name, &bytes, &hbc1, &mut v98_equiv_passed, &mut v98_byte_identical);
        } else if HbcFileEquiv::<V99>::new(&hbc1).is_some() {
            v99_checked += 1;
            check_v99_roundtrip(name, &bytes, &hbc1, &mut v99_equiv_passed, &mut v99_byte_identical);
        } else {
            eprintln!(
                "SKIP unsupported-version: {name} (version = {}; v1 scope is v84+v96+v98+v99)",
                hbc1.version
            );
            unsupported_version_skipped += 1;
        }
    }

    eprintln!(
        "\n## CORPUS ROUND-TRIP SUMMARY\n\
         v84 checked:               {v84_checked}\n\
         HbcFileEquiv<V84>:         {v84_equiv_passed}\n\
         v84 byte-identical:        {v84_byte_identical}\n\
         v96 checked:               {v96_checked}\n\
         HbcFileEquiv<V96>:         {v96_equiv_passed}\n\
         v96 byte-identical:        {v96_byte_identical}\n\
         v98 checked:               {v98_checked}\n\
         HbcFileEquiv<V98>:         {v98_equiv_passed}\n\
         v98 byte-identical:        {v98_byte_identical}\n\
         v99 checked:               {v99_checked}\n\
         HbcFileEquiv<V99>:         {v99_equiv_passed}\n\
         v99 byte-identical:        {v99_byte_identical}\n\
         unsupported-version skip:  {unsupported_version_skipped}\n\
         parse failed:              {parse_failed}\n"
    );

    assert_eq!(
        v84_checked, v84_equiv_passed,
        "{v84_checked} v84 samples checked but only {v84_equiv_passed} passed HbcFileEquiv"
    );
    assert_eq!(
        v84_checked, v84_byte_identical,
        "{v84_checked} v84 samples checked but only {v84_byte_identical} byte-identical"
    );
    assert_eq!(
        v96_checked, v96_equiv_passed,
        "{v96_checked} v96 samples checked but only {v96_equiv_passed} passed HbcFileEquiv"
    );
    assert_eq!(
        v96_checked, v96_byte_identical,
        "{v96_checked} v96 samples checked but only {v96_byte_identical} byte-identical — \
         byte-identity is a theorem of correct emit on clean inputs; regression here halts"
    );
    assert_eq!(
        v98_checked, v98_equiv_passed,
        "{v98_checked} v98 samples checked but only {v98_equiv_passed} passed HbcFileEquiv"
    );
    assert_eq!(
        v98_checked, v98_byte_identical,
        "{v98_checked} v98 samples checked but only {v98_byte_identical} byte-identical — \
         byte-identity is a theorem of correct emit on clean inputs; regression here halts"
    );
    assert_eq!(
        v99_checked, v99_equiv_passed,
        "{v99_checked} v99 samples checked but only {v99_equiv_passed} passed HbcFileEquiv"
    );
    assert_eq!(
        v99_checked, v99_byte_identical,
        "{v99_checked} v99 samples checked but only {v99_byte_identical} byte-identical"
    );
    assert!(
        v84_checked > 0 || v96_checked > 0 || v98_checked > 0 || v99_checked > 0,
        "corpus dir {} has zero v84/v96/v98/v99 samples; staging discipline broken",
        dir.display()
    );
}

fn check_v84_roundtrip(
    name: &str,
    bytes: &[u8],
    hbc1: &HbcFile<'_>,
    equiv_passed: &mut u32,
    byte_identical: &mut u32,
) {
    let equiv1 = HbcFileEquiv::<V84>::new(hbc1).expect("caller gated on v84");
    let emitted =
        emit_hbc_v84(hbc1).unwrap_or_else(|e| panic!("emit_hbc_v84 failed on sample {name}: {e}"));
    let hbc2 = HbcFile::parse(&emitted, None)
        .unwrap_or_else(|e| panic!("second parse failed on v84 sample {name}: {e:?}"));
    let equiv2 = HbcFileEquiv::<V84>::new(&hbc2)
        .unwrap_or_else(|| panic!("emit_hbc_v84 output non-v84 for sample {name}"));

    assert!(
        equiv1 == equiv2,
        "HbcFileEquiv<V84> violated round-trip for sample {name}\n  \
         src_len={} emit_len={}",
        bytes.len(),
        emitted.len(),
    );
    *equiv_passed += 1;

    if bytes == emitted {
        *byte_identical += 1;
        eprintln!(
            "OK: {name} ({} bytes) — HbcFileEquiv<V84> holds + byte-identical",
            bytes.len()
        );
    } else {
        let diff_count = bytes.iter().zip(emitted.iter()).filter(|(a, b)| a != b).count();
        let first_diff = bytes
            .iter()
            .zip(emitted.iter())
            .enumerate()
            .find(|(_, (a, b))| a != b)
            .map(|(i, _)| i);
        panic!(
            "byte-identity regression on {name}: {diff_count} v84 byte-diffs \
             (first at offset {first_diff:?}); src_len={} emit_len={}",
            bytes.len(),
            emitted.len()
        );
    }
}

fn check_v96_roundtrip(
    name: &str,
    bytes: &[u8],
    hbc1: &HbcFile<'_>,
    equiv_passed: &mut u32,
    byte_identical: &mut u32,
) {
    let equiv1 = HbcFileEquiv::<V96>::new(hbc1).expect("caller gated on v96");
    let emitted = emit_hbc(hbc1).unwrap_or_else(|e| panic!("emit failed on v96 sample {name}: {e}"));
    let hbc2 = HbcFile::parse(&emitted, None)
        .unwrap_or_else(|e| panic!("second parse failed on v96 sample {name}: {e:?}"));
    let equiv2 = HbcFileEquiv::<V96>::new(&hbc2)
        .unwrap_or_else(|| panic!("emit output non-v96 for sample {name}"));

    assert!(
        equiv1 == equiv2,
        "HbcFileEquiv<V96> violated round-trip for sample {name}\n  \
         src_len={} emit_len={}",
        bytes.len(),
        emitted.len(),
    );
    *equiv_passed += 1;

    if bytes == emitted {
        *byte_identical += 1;
        eprintln!(
            "OK: {name} ({} bytes) — HbcFileEquiv<V96> holds + byte-identical",
            bytes.len()
        );
    } else {
        let diff_count = bytes.iter().zip(emitted.iter()).filter(|(a, b)| a != b).count();
        let first_diff = bytes
            .iter()
            .zip(emitted.iter())
            .enumerate()
            .find(|(_, (a, b))| a != b)
            .map(|(i, _)| i);
        panic!(
            "byte-identity regression on {name}: {diff_count} v96 byte-diffs \
             (first at offset {first_diff:?}); src_len={} emit_len={}",
            bytes.len(),
            emitted.len()
        );
    }
}

fn check_v99_roundtrip(
    name: &str,
    bytes: &[u8],
    hbc1: &HbcFile<'_>,
    equiv_passed: &mut u32,
    byte_identical: &mut u32,
) {
    let equiv1 = HbcFileEquiv::<V99>::new(hbc1).expect("caller gated on v99");
    let emitted =
        emit_hbc_v99(hbc1).unwrap_or_else(|e| panic!("emit_hbc_v99 failed on sample {name}: {e}"));
    let hbc2 = HbcFile::parse(&emitted, None)
        .unwrap_or_else(|e| panic!("second parse failed on v99 sample {name}: {e:?}"));
    let equiv2 = HbcFileEquiv::<V99>::new(&hbc2)
        .unwrap_or_else(|| panic!("emit_hbc_v99 output non-v99 for sample {name}"));

    assert!(
        equiv1 == equiv2,
        "HbcFileEquiv<V99> violated round-trip for sample {name}\n  \
         src_len={} emit_len={}",
        bytes.len(),
        emitted.len(),
    );
    *equiv_passed += 1;

    if bytes == emitted {
        *byte_identical += 1;
        eprintln!(
            "OK: {name} ({} bytes) — HbcFileEquiv<V99> holds + byte-identical",
            bytes.len()
        );
    } else {
        let diff_count = bytes.iter().zip(emitted.iter()).filter(|(a, b)| a != b).count();
        let first_diff = bytes
            .iter()
            .zip(emitted.iter())
            .enumerate()
            .find(|(_, (a, b))| a != b)
            .map(|(i, _)| i);
        panic!(
            "byte-identity regression on {name}: {diff_count} v99 byte-diffs \
             (first at offset {first_diff:?}); src_len={} emit_len={}",
            bytes.len(),
            emitted.len()
        );
    }
}

fn check_v98_roundtrip(
    name: &str,
    bytes: &[u8],
    hbc1: &HbcFile<'_>,
    equiv_passed: &mut u32,
    byte_identical: &mut u32,
) {
    let equiv1 = HbcFileEquiv::<V98>::new(hbc1).expect("caller gated on v98");
    let emitted =
        emit_hbc_v98(hbc1).unwrap_or_else(|e| panic!("emit_hbc_v98 failed on sample {name}: {e}"));
    let hbc2 = HbcFile::parse(&emitted, None)
        .unwrap_or_else(|e| panic!("second parse failed on v98 sample {name}: {e:?}"));
    let equiv2 = HbcFileEquiv::<V98>::new(&hbc2)
        .unwrap_or_else(|| panic!("emit_hbc_v98 output non-v98 for sample {name}"));

    assert!(
        equiv1 == equiv2,
        "HbcFileEquiv<V98> violated round-trip for sample {name}\n  \
         src_len={} emit_len={}",
        bytes.len(),
        emitted.len(),
    );
    *equiv_passed += 1;

    if bytes == emitted {
        *byte_identical += 1;
        eprintln!(
            "OK: {name} ({} bytes) — HbcFileEquiv<V98> holds + byte-identical",
            bytes.len()
        );
    } else {
        let diff_count = bytes.iter().zip(emitted.iter()).filter(|(a, b)| a != b).count();
        let first_diff = bytes
            .iter()
            .zip(emitted.iter())
            .enumerate()
            .find(|(_, (a, b))| a != b)
            .map(|(i, _)| i);
        panic!(
            "byte-identity regression on {name}: {diff_count} v98 byte-diffs \
             (first at offset {first_diff:?}); src_len={} emit_len={}",
            bytes.len(),
            emitted.len()
        );
    }
}
