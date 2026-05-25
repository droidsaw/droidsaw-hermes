//! `hbc_triage` — point-and-shoot forensic classifier for a single HBC
//! bundle. Reports version, counts, `debug_info` classification,
//! filename-storage disclosure (when present), and source-info
//! coverage ratio — then annotates findings with RE-interpretation
//! remarks (e.g. "ships-with-source is unusual for production RN").
//!
//! Designed as a demo of the `DebugInfoClassification` +
//! `debug_filenames_utf8` + `source_info_coverage_ratio` accessors.
//! No corpus dependency; operates on any user-supplied `.hbc` path.
//!
//! ```
//! cargo run --release --example hbc_triage -- /path/to/bundle.hbc
//! ```
//!
//! Exit code: 0 on successful triage (including all classifications),
//! 1 on I/O or parse failure.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "PROOF: HBC parser/decompiler. IDs (string-id, builtin-id, function-id, regex-id) are widened from parser-validated u32 header counts and narrowed via explicit width-bounded ops. Slot/level-id narrows carry explicit `& 0xFFFF` / `& 0xFF` masks at the cast site. See module-level Cast hygiene doc-comment. PROOF: HBC's BigInt sign-encoding + jump-offset signed/unsigned reinterpretation; values originate from validated-width operands."
)]

use droidsaw_hermes::parser::{DebugInfoClassification, HbcFile};
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: hbc_triage <path-to-hbc-file>");
        return ExitCode::from(1);
    };

    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ERR: read {path}: {e}");
            return ExitCode::from(1);
        }
    };

    let hbc = match HbcFile::parse(&bytes, None) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("ERR: parse {path}: {e:?}");
            return ExitCode::from(1);
        }
    };

    println!("== {} ({} bytes) ==", path, bytes.len());
    println!("  Version:         v{}", hbc.version);
    println!("  Function count:  {}", fmt_num(hbc.function_count.into()));
    println!("  String count:    {}", fmt_num(hbc.string_count.into()));
    println!("  RegExp count:    {}", fmt_num(hbc.regexp_count().into()));
    println!("  BigInt count:    {}", fmt_num(hbc.bigint_count().into()));

    let classification = hbc.debug_info_classification();
    println!("  Debug info:      {}", classification_label(classification));

    let mut remarks: Vec<String> = Vec::new();

    match classification {
        DebugInfoClassification::Absent => {
            remarks.push(
                "No debug_info section at all. Consistent with an aggressively \
                 stripped build or a build-config that omits the section slot entirely."
                    .into(),
            );
        }
        DebugInfoClassification::HeaderOnly => {
            remarks.push(
                "Default production-RN posture — source mapping stripped to save \
                 bundle size. DebugInfoHeader is present but payload is empty."
                    .into(),
            );
        }
        DebugInfoClassification::Full => {
            remarks.push(
                "UNUSUAL for production RN — builder retained source mapping. \
                 Most production bundles strip this; retained source is often a \
                 build-config choice for crash-reporting pipelines."
                    .into(),
            );

            if let Some(fname_bytes) = hbc.debug_filenames_utf8() {
                println!(
                    "  Filename storage: {} bytes",
                    fmt_num(fname_bytes.len() as u64)
                );
                match std::str::from_utf8(fname_bytes) {
                    Ok(s) => {
                        println!("    {}", escape_for_terminal(s));
                        remarks.push(format!(
                            "Filename discloses build path ({} bytes of UTF-8). \
                             May reveal CI layout, internal repo structure, or \
                             build-task naming — RE forensic signal.",
                            fname_bytes.len()
                        ));
                    }
                    Err(_) => {
                        println!("    <non-UTF-8; {} bytes raw>", fname_bytes.len());
                        remarks.push(
                            "Filename storage is not valid UTF-8 — unusual; may \
                             indicate mangled / encoded / foreign-encoding content."
                                .into(),
                        );
                    }
                }
            }

            if let Some(cov) = hbc.source_info_coverage_ratio() {
                println!(
                    "  Source coverage: {:.1}% ({} of {} functions)",
                    cov * 100.0,
                    fmt_num(
                        (cov * f64::from(hbc.function_count) as f32) as u64
                    ),
                    fmt_num(hbc.function_count.into()),
                );
                if (0.80..=0.98).contains(&cov) {
                    remarks.push(format!(
                        "Coverage {:.1}% is within Hermes's typical selective range. \
                         Synthetic / transpiler / native-binding functions are \
                         legitimately excluded from source mapping.",
                        cov * 100.0
                    ));
                } else if cov < 0.50 {
                    remarks.push(format!(
                        "Coverage {:.1}% is ANOMALOUSLY LOW. May indicate selective \
                         stripping of specific functions — worth manual inspection \
                         of which function indices lack source info.",
                        cov * 100.0
                    ));
                } else if cov > 0.98 {
                    remarks.push(format!(
                        "Coverage {:.1}% is unusually HIGH. May indicate a \
                         development/debug build rather than a stripped release.",
                        cov * 100.0
                    ));
                }
            }

            if let Some(lex) = hbc.lexical_data_bytes() {
                println!("  Lexical data:    {} bytes (not decomposed)", fmt_num(lex.len() as u64));
                if lex.len() > 1024 {
                    remarks.push(format!(
                        "Lexical data region is {} bytes — substantial scope-chain/\
                         variable-name content. Not decomposed by this tool; raw \
                         bytes available via `HbcFile::lexical_data_bytes()`.",
                        fmt_num(lex.len() as u64)
                    ));
                }
            }
        }
    }

    if hbc.version != 96 {
        remarks.push(format!(
            "Parser v1 scope is HBC v96; this sample is v{}. Debug-info \
             decomposition path was skipped (layout differs by version).",
            hbc.version
        ));
    }

    if !remarks.is_empty() {
        println!();
        println!("Remarks:");
        for r in remarks {
            for (i, line) in wrap_str(&r, 74).iter().enumerate() {
                if i == 0 {
                    println!("  * {line}");
                } else {
                    println!("    {line}");
                }
            }
        }
    }

    ExitCode::from(0)
}

fn classification_label(c: DebugInfoClassification) -> &'static str {
    match c {
        DebugInfoClassification::Absent => "Absent (no debug_info section)",
        DebugInfoClassification::HeaderOnly => "HeaderOnly (payload stripped)",
        DebugInfoClassification::Full => "Full (ships with source info)",
    }
}

/// Format a number with thousands separators for readability.
fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let chars: Vec<char> = s.chars().rev().collect();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in chars.iter().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(*c);
    }
    out.chars().rev().collect()
}

/// Escape a string for terminal display (non-printable → \xHH).
fn escape_for_terminal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_graphic() || c == ' ' || c == '/' {
            out.push(c);
        } else {
            for b in c.to_string().bytes() {
                out.push_str(&format!("\\x{:02x}", b));
            }
        }
    }
    out
}

/// Word-wrap a string to a given column width for readable remark
/// output.
fn wrap_str(s: &str, width: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    for word in s.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.len() + 1 + word.len() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}
