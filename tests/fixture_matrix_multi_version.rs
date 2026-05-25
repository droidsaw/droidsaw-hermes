//! Multi-version language fixture matrix for `droidsaw-hermes`.
//!
//! Iterates `$DROIDSAW_HERMES_MULTI_VERSION_CORPUS/{v40,v76,v96}/*.hbc` and runs
//! `parse → decompile → recompile-via-hermesc` per sample. Asserts the
//! invariant `∀ s ∈ samples(v96), if decompile(v96, s) succeeds → SEMANTIC_FAIL
//! = 0`.
//!
//! Only v96 is ratcheted; v40 + v76 are placeholders pending corpus
//! sourcing (see `tests/fixtures/multi_version/{v40,v76}/README.md`).
//! Their ratchet contribution kicks in only when corpus is staged.
//!
//! Skips cleanly when the env var isn't set or `hermesc` isn't on PATH — cold
//! clones / CI without the corpus see `SKIP` lines, not failures. Staging
//! instructions live in `tests/fixtures/multi_version/v96/README.md`.
//!
//! Distinct from sibling tests:
//! - `tests/fixture_ratchet.rs` — synthetic source fixtures × hermesc, golden-
//!   locked decompile.
//! - `tests/hbc_corpus_roundtrip.rs` — env-gated parse+emit byte-identity (no
//!   decompile).
//!
//! This test fills the corpus-sample × decompile-soundness slice.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use droidsaw_hermes::decompile::decompile_bundle;
use droidsaw_hermes::parser::HbcFile;

const CORPUS_ENV: &str = "DROIDSAW_HERMES_MULTI_VERSION_CORPUS";

/// Versions enumerated in the matrix. v40 + v76 are pending corpus
/// sourcing; v96 is the only ratcheted column.
const MATRIX_VERSIONS: &[u32] = &[40, 76, 96];

/// On-disk magic of an HBC bundle (LE storage of upstream constant
/// `0x1F1903C103BC1FC6`). 8 bytes at offset 0.
const HBC_MAGIC: [u8; 8] = [0xC6, 0x1F, 0xBC, 0x03, 0xC1, 0x03, 0x19, 0x1F];

#[derive(Debug, Default)]
struct VersionTally {
    success: u32,
    compile_fail: u32,
    semantic_fail: u32,
    wrong_version_skip: u32,
    parse_fail: u32,
}

#[test]
fn multi_version_matrix() {
    let Some(corpus_root) = resolve_corpus_root() else {
        eprintln!(
            "SKIP: {CORPUS_ENV} not set or not a directory; \
             see tests/fixtures/multi_version/v96/README.md for staging"
        );
        return;
    };
    let Some(hermesc) = resolve_hermesc() else {
        eprintln!(
            "SKIP: hermesc not found on PATH or known build path; \
             see tests/README.md for toolchain setup"
        );
        return;
    };

    let mut tallies: BTreeMap<u32, VersionTally> = BTreeMap::new();
    for &version in MATRIX_VERSIONS {
        let mut tally = VersionTally::default();
        let subdir = corpus_root.join(format!("v{version}"));
        let samples = hbc_samples(&subdir);
        if samples.is_empty() {
            eprintln!(
                "  v{version} skipped — 0 samples in {} \
                 (placeholder dir; see README.md)",
                subdir.display()
            );
            tallies.insert(version, tally);
            continue;
        }

        for path in &samples {
            classify_sample(&hermesc, version, path, &mut tally);
        }
        tallies.insert(version, tally);
    }

    print_summary(&tallies);

    let v96 = tallies.get(&96).expect("v96 enumerated above");
    assert_eq!(
        v96.semantic_fail, 0,
        "v96 SEMANTIC_FAIL ratchet: {} sample(s) failed the decompile-soundness \
         invariant (decompile produced text that hermesc accepts but is \
         semantically wrong); ratchet must hold at 0",
        v96.semantic_fail,
    );
}

fn classify_sample(hermesc: &Path, expected_version: u32, path: &Path, tally: &mut VersionTally) {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("<?>");
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("  v{expected_version}/{name}: read error {e}; skipping");
            return;
        }
    };
    let actual_version = match probe_version(&bytes) {
        Some(v) => v,
        None => {
            eprintln!("  v{expected_version}/{name}: not an HBC bundle (magic mismatch)");
            tally.wrong_version_skip += 1;
            return;
        }
    };
    if actual_version != expected_version {
        eprintln!(
            "  v{expected_version}/{name}: version stamp v{actual_version} != \
             dir v{expected_version}; skipping (staging error)"
        );
        tally.wrong_version_skip += 1;
        return;
    }

    let hbc = match HbcFile::parse(&bytes, None) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("  v{expected_version}/{name}: parse failed {e:?}");
            tally.parse_fail += 1;
            return;
        }
    };

    let funcs: Vec<String> = decompile_bundle(&hbc, &bytes, true)
        .into_iter()
        .map(|r| r.unwrap_or_default())
        .collect();
    if funcs.iter().all(|s| s.is_empty()) {
        eprintln!("  v{expected_version}/{name}: SEMANTIC_FAIL (decompile produced no functions)");
        tally.semantic_fail += 1;
        return;
    }
    let decompiled = concat_functions(&funcs);

    match invoke_hermesc(hermesc, &decompiled) {
        Ok(()) => {
            eprintln!("  v{expected_version}/{name}: SUCCESS ({} bytes)", bytes.len());
            tally.success += 1;
        }
        Err(stderr) => {
            eprintln!(
                "  v{expected_version}/{name}: COMPILE_FAIL on recompile — {}",
                truncate(&stderr, 256)
            );
            tally.compile_fail += 1;
        }
    }
}

fn probe_version(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 12 || bytes[..8] != HBC_MAGIC {
        return None;
    }
    let v = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    Some(v)
}

fn concat_functions(funcs: &[String]) -> String {
    let mut out = String::new();
    for text in funcs {
        out.push_str(text);
        if !text.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

fn invoke_hermesc(hermesc: &Path, source: &str) -> Result<(), String> {
    let tmp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let src_path = tmp.path().join("src.js");
    let hbc_path = tmp.path().join("out.hbc");
    std::fs::write(&src_path, source).map_err(|e| format!("write src: {e}"))?;
    let out = Command::new(hermesc)
        .arg("-emit-binary")
        .arg("-out")
        .arg(&hbc_path)
        .arg(&src_path)
        .output()
        .map_err(|e| format!("hermesc spawn: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n { s.to_string() } else { format!("{}…", &s[..n]) }
}

fn print_summary(tallies: &BTreeMap<u32, VersionTally>) {
    eprintln!("\n## MULTI-VERSION MATRIX SUMMARY (v96 ratcheted; v40+v76 pending corpus)");
    for (version, tally) in tallies {
        let total = tally.success
            + tally.compile_fail
            + tally.semantic_fail
            + tally.wrong_version_skip
            + tally.parse_fail;
        eprintln!(
            "  v{version}: total={total:<3} success={:<3} compile_fail={:<3} \
             semantic_fail={:<3} wrong_version_skip={:<3} parse_fail={}",
            tally.success,
            tally.compile_fail,
            tally.semantic_fail,
            tally.wrong_version_skip,
            tally.parse_fail
        );
    }
    eprintln!(
        "  Ratchet invariant: ∀ s ∈ samples(v96), \
         decompile(v96, s) succeeds → SEMANTIC_FAIL(v96, s) = 0\n"
    );
}

fn hbc_samples(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
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

fn resolve_corpus_root() -> Option<PathBuf> {
    let raw = std::env::var(CORPUS_ENV).ok()?;
    let path = PathBuf::from(raw);
    if path.is_dir() { Some(path) } else { None }
}

/// Mirror of `tests/fixture_ratchet.rs::resolve_hermesc` — kept duplicated to
/// avoid hoisting test-only helpers into the harness library.
fn resolve_hermesc() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("DROIDSAW_HERMESC") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    if let Ok(out) = Command::new("which").arg("hermesc").output() {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !s.is_empty() {
            return Some(PathBuf::from(s));
        }
    }
    if cfg!(target_os = "linux") {
        // Fallback: a hermesc built from source under $HOME.
        if let Ok(home) = std::env::var("HOME") {
            let known = PathBuf::from(format!(
                "{home}/droidsaw/droidsaw/droidsaw-hbc/hermes/build-x86_64/bin/hermesc"
            ));
            if known.exists() {
                return Some(known);
            }
        }
    }
    None
}
