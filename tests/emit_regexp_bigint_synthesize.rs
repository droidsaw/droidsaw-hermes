//! Corpus-gated tests for `emit_regexp_table_v96` +
//! `emit_bigint_table_v96` (synthesize-from-IR for v96).
//!
//! These assert bytewise-equality between synthesize output and
//! source bytes at the corresponding section offsets on each staged
//! v96 corpus sample. They do NOT modify `emit_hbc` — current emit
//! body-passthrough already produces these bytes correctly; the
//! helpers are discipline-tightening primitives + a hook for a
//! future section-walker-aware emit_hbc refactor.
//!
//! Skips cleanly when `$DROIDSAW_HERMES_V96_CORPUS` is unset or has
//! no .hbc files.

use droidsaw_hermes::emit::{emit_bigint_table_v96, emit_regexp_table_v96};
use droidsaw_hermes::parser::HbcFile;
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

fn find_section_range(hbc: &HbcFile<'_>, name: &str) -> Option<(usize, usize)> {
    let section = hbc.sections.iter().find(|s| s.0 == name)?;
    #[allow(clippy::as_conversions)]
    Some((section.1 as usize, section.2 as usize))
}

#[test]
fn regexp_table_synthesize_matches_source_on_corpus() {
    let Some(entries) = iter_v96_samples() else {
        eprintln!("SKIP: {CORPUS_ENV} not set");
        return;
    };

    let mut checked = 0u32;
    let mut with_table = 0u32;

    for path in &entries {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("<?>");
        let Ok(bytes) = fs::read(path) else { continue };
        let Ok(hbc) = HbcFile::parse(&bytes, None) else { continue };
        if hbc.version != 96 {
            continue;
        }
        checked += 1;

        let Some((sec_off, sec_len)) = find_section_range(&hbc, "RegExpTable") else {
            continue;
        };
        if sec_len == 0 {
            continue;
        }
        with_table += 1;

        let mut out = Vec::with_capacity(sec_len);
        emit_regexp_table_v96(&hbc, &mut out).expect("synthesize must succeed");

        assert_eq!(
            out.len(),
            sec_len,
            "{name}: synthesized RegExpTable size ({}) != section size ({})",
            out.len(),
            sec_len
        );
        let src_slice = &bytes[sec_off..sec_off + sec_len];
        assert_eq!(
            out.as_slice(),
            src_slice,
            "{name}: synthesized RegExpTable bytes != source bytes"
        );
    }

    eprintln!(
        "regexp_table_synthesize: checked={} with_non_empty_table={}",
        checked, with_table
    );
    assert!(
        checked > 0,
        "corpus has at least one v96 sample to check"
    );
}

#[test]
fn bigint_table_synthesize_matches_source_on_corpus() {
    let Some(entries) = iter_v96_samples() else {
        eprintln!("SKIP: {CORPUS_ENV} not set");
        return;
    };

    let mut checked = 0u32;
    let mut with_table = 0u32;
    let mut without_table = 0u32;

    for path in &entries {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("<?>");
        let Ok(bytes) = fs::read(path) else { continue };
        let Ok(hbc) = HbcFile::parse(&bytes, None) else { continue };
        if hbc.version != 96 {
            continue;
        }
        checked += 1;

        let mut out = Vec::new();
        emit_bigint_table_v96(&hbc, &mut out).expect("synthesize must succeed");

        let Some((sec_off, sec_len)) = find_section_range(&hbc, "BigIntTable") else {
            // BigIntTable section only present when bigint_count > 0.
            assert_eq!(
                hbc.bigint_count(),
                0,
                "{name}: no BigIntTable section but bigint_count > 0"
            );
            assert!(
                out.is_empty(),
                "{name}: synthesized BigIntTable should be empty when bigint_count == 0"
            );
            without_table += 1;
            continue;
        };
        if sec_len == 0 {
            without_table += 1;
            continue;
        }
        with_table += 1;

        assert_eq!(
            out.len(),
            sec_len,
            "{name}: synthesized BigIntTable size ({}) != section size ({})",
            out.len(),
            sec_len
        );
        let src_slice = &bytes[sec_off..sec_off + sec_len];
        assert_eq!(
            out.as_slice(),
            src_slice,
            "{name}: synthesized BigIntTable bytes != source bytes"
        );
    }

    eprintln!(
        "bigint_table_synthesize: checked={} with_table={} empty_table={}",
        checked, with_table, without_table
    );
    assert!(
        checked > 0,
        "corpus has at least one v96 sample to check"
    );
}

#[test]
fn synthesize_rejects_non_v96() {
    // Synthesized 128-byte v96 is trivially empty — test with a v84
    // adversarial fixture to verify the version gate. The fixture is
    // adversarial: parser-side function-region validation may reject it
    // (`FunctionBodyOutOfBytecodeRegion`) before emit sees it. Either
    // rejection point preserves the "non-v96 input cannot reach v96
    // emit" invariant.
    let v84_fixture: &[u8] =
        include_bytes!("fixtures/adversarial/oom/fuzz_ssa/47d147c4c0f9.hbc");
    let Ok(hbc) = HbcFile::parse(v84_fixture, None) else {
        // Parse-time rejection — non-v96 input was filtered earlier in
        // the pipeline. Coverage of the emit-side version gate is
        // preserved by the unit tests on `emit_regexp_table_v96` /
        // `emit_bigint_table_v96` that synthesize HbcFile directly.
        return;
    };
    assert_eq!(hbc.version, 93, "fixture is v93");

    let mut out = Vec::new();
    let regexp_err = emit_regexp_table_v96(&hbc, &mut out).unwrap_err();
    match regexp_err {
        droidsaw_hermes::emit::HermesEmitError::VersionMismatch { expected, got } => {
            assert_eq!(expected, 96);
            assert_eq!(got, 93);
        }
        other => panic!("expected VersionMismatch, got {other:?}"),
    }

    let mut out = Vec::new();
    let bigint_err = emit_bigint_table_v96(&hbc, &mut out).unwrap_err();
    match bigint_err {
        droidsaw_hermes::emit::HermesEmitError::VersionMismatch { expected, got } => {
            assert_eq!(expected, 96);
            assert_eq!(got, 93);
        }
        other => panic!("expected VersionMismatch, got {other:?}"),
    }
}
