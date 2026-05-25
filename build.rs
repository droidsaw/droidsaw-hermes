// build.rs — ORACLE-OPCODE-LOCKSTEP CI gate for droidsaw-hermes.
//
// Ensures that the CF-opcode names enumerated in the production CF predicates
// (src/decompile/decode.rs) are also present in the naive CFG oracle
// (src/decompile/cfg_oracle.rs). If a future production opcode addition is not
// mirrored in the oracle, this gate fails the build before the oracle can silently
// miss divergences.
//
// Design: extract name-string literals from the CF-predicate sections in each
// file via delimited sentinel comments, sort + deduplicate, then assert equality.
// The sentinels are:
//   // ORACLE-OPCODE-LOCKSTEP-BEGIN
//   // ORACLE-OPCODE-LOCKSTEP-END
// Any string literal (double-quoted) found between those sentinels in each file
// is treated as a tracked opcode name. Both files must track the same set.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

fn extract_lockstep_names(path: &Path) -> BTreeSet<String> {
    let content = fs::read_to_string(path).unwrap_or_else(|e| {
        panic!("opcode-lockstep: cannot read {}: {}", path.display(), e);
    });
    let mut inside = false;
    let mut names: BTreeSet<String> = BTreeSet::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.contains("ORACLE-OPCODE-LOCKSTEP-BEGIN") {
            inside = true;
            continue;
        }
        if trimmed.contains("ORACLE-OPCODE-LOCKSTEP-END") {
            inside = false;
            continue;
        }
        if !inside {
            continue;
        }
        // Extract all double-quoted string literals on this line.
        // A string literal is "..." where the content is alphanumeric + underscore.
        // We do a simple scan — no need for a full Rust lexer.
        let mut rest = line;
        while let Some(open) = rest.find('"') {
            rest = &rest[open + 1..];
            if let Some(close) = rest.find('"') {
                let candidate = &rest[..close];
                // Only track opcode-name literals (non-empty, no spaces, no backslashes).
                if !candidate.is_empty() && !candidate.contains(' ') && !candidate.contains('\\') {
                    names.insert(candidate.to_string());
                }
                rest = &rest[close + 1..];
            } else {
                break;
            }
        }
    }
    names
}

fn main() {
    let decode_path = Path::new("src/decompile/decode.rs");
    let oracle_path = Path::new("src/decompile/cfg_oracle.rs");

    println!("cargo::rerun-if-changed=src/decompile/decode.rs");
    println!("cargo::rerun-if-changed=src/decompile/cfg_oracle.rs");

    // Only run the gate when the oracle module is present (it's cfg-gated for test/fuzz).
    // If the oracle file doesn't exist, skip silently — Phase 4 hasn't landed yet.
    if !oracle_path.exists() {
        return;
    }

    let prod_names = extract_lockstep_names(decode_path);
    let oracle_names = extract_lockstep_names(oracle_path);

    if prod_names.is_empty() && oracle_names.is_empty() {
        // Sentinels missing from both files — skip with a warning.
        println!(
            "cargo::warning=opcode-lockstep: ORACLE-OPCODE-LOCKSTEP-BEGIN/END sentinels not \
            found in decode.rs or cfg_oracle.rs — gate is inactive. Add sentinels to activate."
        );
        return;
    }

    if prod_names != oracle_names {
        let only_prod: Vec<_> = prod_names.difference(&oracle_names).collect();
        let only_oracle: Vec<_> = oracle_names.difference(&prod_names).collect();
        panic!(
            "opcode-lockstep FAIL: CF opcode name sets diverge.\n\
            Only in production (decode.rs): {only_prod:?}\n\
            Only in oracle (cfg_oracle.rs): {only_oracle:?}\n\
            Update the oracle's ORACLE-OPCODE-LOCKSTEP section to match production."
        );
    }
}
