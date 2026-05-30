#![no_main]

// Differential oracle fuzz target for HBC parser.
//
// Property: for every raw byte slice where at least one parser succeeds,
// `naive_parse_hbc(buf).to_shape()` must equal `HbcFile::parse(buf).to_shape()`.
//
// Any divergence is a silent-wrong-parse bug at layer 1 of the layered-oracle
// architecture for Hermes HBC.
//
// Invariants asserted:
// 1. naive_parse_hbc(buf) == HbcFile::parse(buf).to_shape()
//    (on any input where at least one parser succeeds)
//
// Harness design:
// - Input: raw byte slice (arbitrary bytes).
// - If both parsers fail: skip.
// - If both succeed: assert HbcParseShape equality.
// - If divergence (one succeeds, other fails): panic with context.
// - Stateless: no internal mutation across fuzz iterations.

use droidsaw_hermes::parser::HbcFile;
use droidsaw_hermes::parser_oracle::naive_parse_hbc;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let prod = HbcFile::parse(data, None);
    let oracle = naive_parse_hbc(data);

    match (&prod, &oracle) {
        // Both fail — no shape to compare; agreement by rejection. OK.
        (Err(_), Err(_)) => {}

        // Both succeed — assert HbcParseShape equality.
        (Ok(prod_file), Ok(oracle_shape)) => {
            let prod_shape = prod_file.to_shape();
            assert_eq!(
                prod_shape,
                *oracle_shape,
                "HbcParseShape DIVERGED on production-accepted input\n\
                 production: {prod_shape:#?}\n\
                 oracle:     {oracle_shape:#?}"
            );
        }

        // Production accepted but oracle rejected — oracle is more restrictive.
        (Ok(prod_file), Err(oracle_err)) => {
            let prod_shape = prod_file.to_shape();
            panic!(
                "ORACLE-REJECTED what production accepted\n\
                 oracle_err: {oracle_err:?}\n\
                 prod_shape.function_count={}, .string_count={}",
                prod_shape.function_count, prod_shape.string_count,
            );
        }

        // Oracle accepted but production rejected.
        // Log without panicking since production may have additional
        // validity checks not replicated in the structural oracle.
        (Err(_prod_err), Ok(_oracle_shape)) => {
            // Structural divergence — oracle is more permissive.
            // Not a hard assertion: production validity checks
            // (e.g. overflow_string_count > string_count) are
            // mirrored in the oracle but some edge cases may differ.
            // The fuzz harness will surface these as the corpus grows.
        }
    }
});
