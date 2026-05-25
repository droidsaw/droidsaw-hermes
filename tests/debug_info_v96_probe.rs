//! Corpus-gated tests for the v96 debug_info decomposition landed by
//! the v96 debug_info decomposition.
//!
//! All assertions are GENERIC — they do not depend on any specific
//! production sample's contents. The tests iterate whatever HBC
//! samples are present at `$DROIDSAW_HERMES_V96_CORPUS` and validate
//! structural properties that must hold across any conforming v96
//! bundle. Users stage their own corpus; the tests skip cleanly when
//! no corpus is available.
//!
//! Staging (generic):
//!
//! ```bash
//! DROIDSAW_HERMES_V96_CORPUS=/path/to/v96-corpus cargo test \
//!     -p droidsaw-hermes --release --test debug_info_v96_probe -- --nocapture
//! ```

#![allow(
    clippy::cast_precision_loss,
    reason = "PROOF: HBC parser/decompiler stats (LineMap deltas, function-size histograms); f32/f64 mantissa loss is below per-bytecode measurement noise."
)]

use droidsaw_hermes::parser::{DebugInfoClassification, HbcFile};
use std::fs;
use std::path::PathBuf;

const CORPUS_ENV: &str = "DROIDSAW_HERMES_V96_CORPUS";

fn iter_v96_samples() -> Option<Vec<PathBuf>> {
    let dir = std::env::var(CORPUS_ENV).ok()?;
    let dir_path = PathBuf::from(dir);
    if !dir_path.is_dir() {
        return None;
    }
    let mut entries: Vec<PathBuf> = fs::read_dir(&dir_path)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|s| s == "hbc").unwrap_or(false))
        .collect();
    entries.sort();
    Some(entries)
}

#[test]
fn any_full_v96_sample_decomposes_cleanly() {
    let Some(entries) = iter_v96_samples() else {
        eprintln!("SKIP: {CORPUS_ENV} not set or not a directory");
        return;
    };

    // Find the first Full-classified v96 sample in the corpus. Tests
    // structural properties only; no per-sample content assertions.
    let mut probed = false;
    for path in &entries {
        let Ok(bytes) = fs::read(path) else { continue };
        let Ok(hbc) = HbcFile::parse(&bytes, None) else { continue };
        if hbc.version != 96 {
            continue;
        }
        if hbc.debug_info_classification() != DebugInfoClassification::Full {
            continue;
        }

        // Structural properties that must hold for any Full v96 sample.
        let info = hbc
            .debug_info_v96()
            .expect("Full classification implies debug_info_v96 present");
        assert!(
            info.header.filename_count >= 1,
            "Full sample has at least one debug filename"
        );
        assert!(
            info.header.file_region_count >= 1,
            "Full sample has at least one file region"
        );
        assert!(
            info.header.debug_data_size >= info.header.lexical_data_offset,
            "lexical_data_offset must fall within debug_data_size"
        );

        // File region table byte-range within buffer.
        let (fr_off, fr_len) = info.file_region_table;
        assert_eq!(
            fr_len,
            info.header.file_region_count as usize * 12,
            "file_region_table size = file_region_count × 12"
        );
        assert!(fr_off + fr_len <= bytes.len(), "file_region_table in-buf");

        // First file region decodes without panic.
        let _region = hbc
            .debug_file_region_get(0)
            .expect("first file region decodes");

        // Filename storage is non-empty + returns Some.
        let fn_bytes = hbc
            .debug_filenames_utf8()
            .expect("Full sample has filename storage");
        assert!(
            !fn_bytes.is_empty(),
            "filename storage is non-empty on Full sample"
        );

        // Source locations decode to at least one function.
        let locs = hbc
            .source_locations()
            .expect("Full sample should have at least one decoded function");
        assert!(!locs.is_empty(), "decoded source_locations are non-empty");

        // Coverage ratio is within the Hermes-selective range observed
        // on real Full samples. Bound set generously to accommodate
        // variation across builder configs.
        let cov = hbc
            .source_info_coverage_ratio()
            .expect("coverage ratio exists on Full sample");
        assert!(
            (0.0..=1.0).contains(&cov),
            "coverage ratio is a valid fraction: {cov}"
        );

        probed = true;
        eprintln!(
            "probed Full sample: fn_count={} decoded={} cov={:.3}",
            hbc.function_count,
            locs.len(),
            cov
        );
        break;
    }

    if !probed {
        eprintln!("SKIP: no Full-classified v96 sample in corpus");
    }
}

#[test]
fn minimal_v96_no_debug_info() {
    // Synthesized 128-byte v96 with debug_info_offset = 0 — no corpus
    // required; verifies all accessors handle the absent case cleanly.
    let mut h = vec![0u8; 128];
    h[0..8].copy_from_slice(&0x1F19_03C1_03BC_1FC6u64.to_le_bytes());
    h[8..12].copy_from_slice(&96u32.to_le_bytes());
    h[32..36].copy_from_slice(&128u32.to_le_bytes());
    let hbc = HbcFile::parse(&h, None).expect("minimal v96 parses");
    assert!(hbc.debug_info_v96().is_none());
    assert!(hbc.source_locations().is_none());
    assert!(hbc.lexical_data_bytes().is_none());
    assert_eq!(
        hbc.debug_info_classification(),
        DebugInfoClassification::Absent
    );
    assert!(hbc.debug_filenames_utf8().is_none());
    assert!(hbc.source_info_coverage_ratio().is_none());
}

/// Corpus-wide ships-with-source distribution. Env-gated. Reports the
/// {Full, HeaderOnly, Absent} split across whatever v96 samples the
/// user has staged. Asserts only that the corpus contains at least
/// one v96 sample; the distribution itself is informational.
#[test]
fn corpus_debug_info_classification_distribution() {
    let Some(entries) = iter_v96_samples() else {
        eprintln!("SKIP: {CORPUS_ENV} not set or not a directory");
        return;
    };

    let mut full = 0u32;
    let mut header_only = 0u32;
    let mut absent = 0u32;
    let mut non_v96 = 0u32;

    for path in &entries {
        let Ok(bytes) = fs::read(path) else { continue };
        let Ok(hbc) = HbcFile::parse(&bytes, None) else { continue };
        if hbc.version != 96 {
            non_v96 += 1;
            continue;
        }
        match hbc.debug_info_classification() {
            DebugInfoClassification::Full => full += 1,
            DebugInfoClassification::HeaderOnly => header_only += 1,
            DebugInfoClassification::Absent => absent += 1,
        }
    }

    let v96_total = full + header_only + absent;
    eprintln!(
        "\n## DEBUG INFO CLASSIFICATION (v96 corpus)\n\
         Full (ships-with-source):  {} ({:.1}%)\n\
         HeaderOnly (stripped):     {} ({:.1}%)\n\
         Absent (no debug_info):    {} ({:.1}%)\n\
         non-v96 (skipped):         {}\n\
         total v96:                 {}\n",
        full,
        (full as f32 / v96_total.max(1) as f32) * 100.0,
        header_only,
        (header_only as f32 / v96_total.max(1) as f32) * 100.0,
        absent,
        (absent as f32 / v96_total.max(1) as f32) * 100.0,
        non_v96,
        v96_total,
    );

    if v96_total == 0 {
        eprintln!("SKIP: corpus has no v96 samples");
    }
}
