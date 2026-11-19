use super::*;

// The expected objects are outputs from TrackMe 9d2e865's TLS parser,
// JA3, JA4 and PeetPrint functions for the corresponding fixed wire bytes.
fn sample(name: &str) -> (Vec<u8>, Value) {
    let fixtures: Value = serde_json::from_str(include_str!("fixtures.json")).unwrap();
    let sample = &fixtures[name];
    (
        hex::decode(sample["body"].as_str().unwrap()).unwrap(),
        sample["expected"].clone(),
    )
}

#[test]
fn tls13_matches_trackme_with_grease_unknowns_and_extension_order() {
    let (body, expected) = sample("modern");
    assert_eq!(describe(&body, 772).unwrap(), expected);
}

#[test]
fn tls12_without_extensions_matches_trackme_nulls_and_empty_hash_inputs() {
    let (body, expected) = sample("legacy");
    assert_eq!(describe(&body, 771).unwrap(), expected);
}

#[test]
fn truncated_extension_vector_is_rejected() {
    let (mut body, _) = sample("modern");
    body.pop();
    assert!(describe(&body, 772).is_err());
}
