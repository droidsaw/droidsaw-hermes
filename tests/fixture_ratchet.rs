//! Tier-1 language-coverage fixture ratchet for `droidsaw-hermes`.
//!
//! For each entry in `tests/fixtures/language_surface/manifest.toml`, runs the
//! `hermesc(src.js) → HbcFile::parse → decompile_bundle → hermesc` pipeline
//! via [`droidsaw_fixture_harness::run_fixture`]. Asserts
//! [`RatchetResult::is_clean`] — any `SemanticFail`, `ResourceLimitExceeded`,
//! `CompilePass`↔`CompileFail` drift, or unknown/missing fixture fails the
//! gate.
//!
//! Unlike the dex sibling (whose `run` step spawns `java` and compares actual
//! stdout), hermes has no JS interpreter in the fixture toolchain — only
//! `hermesc`. So `run` returns the decompiled bundle text, locked against
//! `expected.txt`; `recompile` feeds that text back through `hermesc` as the
//! roundtrip check. Fixtures whose decompile output isn't accepted by
//! `hermesc` land as `CompileFail { stage: Recompile }` and are recorded with
//! `status = "compile_fail"` in the manifest — the honest baseline for the
//! current decompiler's syntactic fidelity.
//!
//! Tools: `hermesc`. Discovered via `DROIDSAW_HERMESC` env var, then `which
//! hermesc`, then a known Linux build path (`.../droidsaw-hbc/hermes/build-
//! x86_64/bin/hermesc`) gated on `cfg!(target_os = "linux")` + presence. When
//! missing, the test skips with `eprintln` rather than hard-failing. See
//! `tests/README.md` for build instructions and `resolve_hermesc` for the
//! precise fallback order.
//!
//! Serial execution: the harness installs `setrlimit(RLIMIT_AS)` which is
//! process-global, so fixtures run in a single `#[test]` that iterates the
//! manifest sequentially.
//!
//! Regen: `cargo test -p droidsaw-hermes --test fixture_ratchet
//! regen_fixtures -- --ignored --nocapture` rebuilds `expected.txt` files and
//! rewrites the manifest's `status` fields to match live outcomes. Run only
//! when intentionally promoting the baseline.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use droidsaw_fixture_harness::{
    CompileStatus, FixtureOutcome, Improvement, Manifest, OutcomeKind, Regression, ResourceCaps,
    Runner, RunnerKind, check_ratchet, check_warnings_strict, run_fixture, skipped_outcome,
};

/// Hoisted to `droidsaw-fixture-harness::fixture_delimiter_prefix` —
/// the harness-side helper is the canonical source of truth.
fn function_delim() -> String {
    droidsaw_fixture_harness::fixture_delimiter_prefix("hermes", "function")
}

const PER_FIXTURE_WALL_TIME: Duration = Duration::from_secs(60);

/// Per-fixture RSS cap. 2 GiB is comfortable for a single `hermesc` subprocess
/// plus the decompile passes; the harness fires `ResourceBudgetNearLimit` at
/// 80 %.
const PER_FIXTURE_RSS: u64 = 2 * 1024 * 1024 * 1024;

#[test]
fn fixture_ratchet() {
    let hermesc = resolve_hermesc();

    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixtures_root = crate_dir.join("tests/fixtures/language_surface");
    let manifest_path = fixtures_root.join("manifest.toml");
    let manifest = Manifest::load(&manifest_path)
        .unwrap_or_else(|e| panic!("load manifest at {manifest_path:?}: {e}"));

    let caps = ResourceCaps {
        wall_time: PER_FIXTURE_WALL_TIME,
        rss_bytes: PER_FIXTURE_RSS,
        kind: RunnerKind::Native,
        ..ResourceCaps::default()
    };

    let mut outcomes: Vec<FixtureOutcome> = Vec::with_capacity(manifest.fixtures.len());
    for entry in &manifest.fixtures {
        let outcome = match &hermesc {
            Some(h) => {
                let runner = HermesFixtureRunner { hermesc: h.clone() };
                run_fixture(runner, entry, &fixtures_root, caps)
            }
            None => skipped_outcome(
                entry.name.clone(),
                "hermesc",
                "hermesc not found; see tests/README.md for toolchain setup",
            ),
        };
        report(&outcome);
        outcomes.push(outcome);
    }

    let result = check_ratchet(&manifest, &outcomes);
    assert!(
        result.is_clean(),
        "hermes fixture ratchet: {} regression(s), {} improvement(s):\n{}",
        result.regressions.len(),
        result.improvements.len(),
        format_findings(&result.regressions, &result.improvements),
    );

    eprintln!(
        "hermes fixture ratchet: {}/{} clean ({} skipped)",
        result.unchanged,
        manifest.fixtures.len(),
        result.skipped,
    );

    check_warnings_strict(&outcomes).expect("strict-warnings gate");
}

/// Regenerates `expected.txt` goldens and rewrites the manifest's `status`
/// field from live outcomes. Run with `--ignored` when promoting the baseline
/// after decompiler changes — never from CI.
#[test]
#[ignore = "baseline-promotion tool: run with `--ignored` to regenerate goldens after intentional decompiler changes. Never from CI."]
fn regen_fixtures() {
    let hermesc = resolve_hermesc().expect("hermesc required for regen");

    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixtures_root = crate_dir.join("tests/fixtures/language_surface");
    let manifest_path = fixtures_root.join("manifest.toml");
    let mut manifest = Manifest::load(&manifest_path)
        .unwrap_or_else(|e| panic!("load manifest at {manifest_path:?}: {e}"));

    for entry in &mut manifest.fixtures {
        let src_path = fixtures_root.join(&entry.source);
        let src = std::fs::read_to_string(&src_path)
            .unwrap_or_else(|e| panic!("read {src_path:?}: {e}"));

        let runner = HermesFixtureRunner {
            hermesc: hermesc.clone(),
        };
        let bytes = match runner.invoke_hermesc(&src) {
            Ok(b) => b,
            Err(e) => panic!("hermesc failed on baseline src {:?}: {e}", entry.source),
        };
        let decompiled = match decompile_bytes(&bytes) {
            Ok(s) => s,
            Err(e) => panic!("baseline decompile of {:?} failed: {e}", entry.source),
        };

        let recompile_status = runner.invoke_hermesc(&decompiled);
        let new_status = if recompile_status.is_ok() {
            CompileStatus::CompilePass
        } else {
            CompileStatus::CompileFail
        };

        // Golden write policy:
        //  - compile_pass fixtures always get `expected.txt` locked bytewise.
        //    If the manifest entry lacks `expected_stdout` (the
        //    COMPILE_FAIL-BASELINE convention), synthesize the conventional
        //    `<feature>/<unit>/expected.txt` path from the source path and
        //    populate it on the entry.
        //  - compile_fail fixtures keep the existing behavior: write the
        //    golden only if the manifest already pointed at one, so failing
        //    entries don't accidentally lock a broken decompile output.
        let golden_rel: Option<PathBuf> = match (&entry.expected_stdout, new_status) {
            (Some(rel), _) => Some(rel.clone()),
            (None, CompileStatus::CompilePass) => entry
                .source
                .parent()
                .map(|dir| dir.join("expected.txt")),
            (None, _) => None,
        };
        if let Some(rel) = &golden_rel {
            let p = fixtures_root.join(rel);
            std::fs::write(&p, &decompiled)
                .unwrap_or_else(|e| panic!("write golden {p:?}: {e}"));
        }
        if entry.expected_stdout.is_none() && new_status == CompileStatus::CompilePass {
            entry.expected_stdout = golden_rel;
        }

        entry.status = new_status;
        eprintln!("  regen {} -> {}", entry.name, entry.status.as_str());
    }

    manifest
        .save(&manifest_path)
        .unwrap_or_else(|e| panic!("save manifest: {e}"));
    eprintln!("regen complete: {} fixtures", manifest.fixtures.len());
}

fn report(outcome: &FixtureOutcome) {
    let tag = match &outcome.kind {
        OutcomeKind::CompilePass => "PASS",
        OutcomeKind::CompileFail { .. } => "COMPILE_FAIL",
        OutcomeKind::SemanticFail { .. } => "SEMANTIC_FAIL",
        OutcomeKind::ResourceLimitExceeded { .. } => "LIMIT",
        OutcomeKind::FixtureReadError { .. } => "READ_ERR",
    };
    eprintln!(
        "  {tag:<13} {} ({:.2}s)",
        outcome.name,
        outcome.wall_time.as_secs_f32()
    );
    for w in &outcome.warnings {
        eprintln!("    warn: {w:?}");
    }
}

fn format_findings(regressions: &[Regression], improvements: &[Improvement]) -> String {
    let mut s = String::new();
    for r in regressions {
        s.push_str(&format!("  - {r:?}\n"));
    }
    for i in improvements {
        s.push_str(&format!("  + {i:?} (update manifest status to compile_pass)\n"));
    }
    s
}

// ─────────────────────────────────────────────────────────────────────────────
// Runner
// ─────────────────────────────────────────────────────────────────────────────

/// Four-arm discovery:
///   1. `$DROIDSAW_HERMESC` env override (tester opts in explicitly).
///   2. `which hermesc` (PATH pickup in cold-clone / CI environments).
///   3. Known local build path — user-specific, gated behind `cfg!(target_os =
///      "linux")` + `Path::exists()` so it's invisible on non-Linux and on
///      cold clones that haven't built hermes.
///   4. None — the test skips with an `eprintln` (see `tests/README.md`).
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

struct HermesFixtureRunner {
    hermesc: PathBuf,
}

/// `Fresh` carries the original `hermesc(src.js)` output — `run`/`decompile`
/// parse + decompile those bytes. `Recompiled` carries a frozen copy of the
/// original decompile text — `run_recompiled` replays it verbatim so the
/// pipeline's `compare(expected, replayed)` only answers "did `hermesc` accept
/// the decompile output?", not "is the HBC bit-stable through a roundtrip?"
/// The latter is out of scope for this tier-1 ratchet: hermes bytecode isn't
/// bijective with source and divergence in re-decompile would surface as
/// spurious `SemanticFail`s.
enum HbcArtifact {
    Fresh { bytes: Vec<u8> },
    Recompiled { locked_text: String },
}

#[derive(Debug)]
enum HermesFixtureError {
    Io { ctx: &'static str, error: String },
    HermescFailed { stderr: String, exit: Option<i32> },
    HbcParse { message: String },
    DecompileEmpty,
}

impl std::fmt::Display for HermesFixtureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { ctx, error } => write!(f, "io[{ctx}]: {error}"),
            Self::HermescFailed { stderr, exit } => {
                write!(f, "hermesc exit={exit:?}: {}", truncate(stderr, 512))
            }
            Self::HbcParse { message } => write!(f, "hbc parse: {}", truncate(message, 512)),
            Self::DecompileEmpty => f.write_str("decompile produced no functions"),
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n { s.to_string() } else { format!("{}…", &s[..n]) }
}

impl HermesFixtureRunner {
    fn invoke_hermesc(&self, source: &str) -> Result<Vec<u8>, HermesFixtureError> {
        let tmp = tempfile::tempdir().map_err(|e| HermesFixtureError::Io {
            ctx: "tempdir",
            error: e.to_string(),
        })?;
        let src_path = tmp.path().join("src.js");
        let hbc_path = tmp.path().join("out.hbc");
        std::fs::write(&src_path, source).map_err(|e| HermesFixtureError::Io {
            ctx: "write src",
            error: e.to_string(),
        })?;
        let out = Command::new(&self.hermesc)
            .arg("-emit-binary")
            .arg("-out")
            .arg(&hbc_path)
            .arg(&src_path)
            .output()
            .map_err(|e| HermesFixtureError::Io {
                ctx: "hermesc spawn",
                error: e.to_string(),
            })?;
        if !out.status.success() {
            return Err(HermesFixtureError::HermescFailed {
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
                exit: out.status.code(),
            });
        }
        std::fs::read(&hbc_path).map_err(|e| HermesFixtureError::Io {
            ctx: "read hbc",
            error: e.to_string(),
        })
    }
}

fn decompile_bytes(bytes: &[u8]) -> Result<String, HermesFixtureError> {
    let hbc = droidsaw_hermes::parser::HbcFile::parse(bytes, None)
        .map_err(|e| HermesFixtureError::HbcParse { message: format!("{e:?}") })?;
    let funcs: Vec<String> = droidsaw_hermes::decompile::decompile_bundle(&hbc, bytes, true)
        .into_iter()
        .map(|r| r.unwrap_or_default())
        .collect();
    if funcs.iter().all(|s| s.is_empty()) {
        return Err(HermesFixtureError::DecompileEmpty);
    }
    let delim = function_delim();
    let mut out = String::new();
    for (fid, text) in funcs.iter().enumerate() {
        out.push_str(&delim);
        out.push_str(&fid.to_string());
        out.push('\n');
        out.push_str(text);
        if !text.ends_with('\n') {
            out.push('\n');
        }
    }
    Ok(out)
}

impl Runner for HermesFixtureRunner {
    type Artifact = HbcArtifact;
    type Error = HermesFixtureError;

    fn compile_source(&self, source: &str) -> Result<HbcArtifact, HermesFixtureError> {
        Ok(HbcArtifact::Fresh {
            bytes: self.invoke_hermesc(source)?,
        })
    }

    fn run(&self, artifact: &HbcArtifact) -> Result<String, HermesFixtureError> {
        match artifact {
            HbcArtifact::Fresh { bytes } => decompile_bytes(bytes),
            HbcArtifact::Recompiled { locked_text } => Ok(locked_text.clone()),
        }
    }

    fn decompile(&self, artifact: &HbcArtifact) -> Result<String, HermesFixtureError> {
        self.run(artifact)
    }

    fn recompile(&self, decompiled: &str) -> Result<HbcArtifact, HermesFixtureError> {
        self.invoke_hermesc(decompiled)?;
        Ok(HbcArtifact::Recompiled {
            locked_text: decompiled.to_string(),
        })
    }
    // run_recompiled defaults to self.run(artifact), which returns locked_text
    // for Recompiled variants.
}
