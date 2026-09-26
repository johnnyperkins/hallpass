#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let (json, keys) = hallpassd::fuzz::syslog(data);
    let value: serde_json::Value =
        serde_json::from_str(&json).unwrap_or_else(|e| panic!("{e}: {json:?}"));
    assert_eq!(
        value.as_object().map(serde_json::Map::len),
        Some(keys),
        "{json:?}"
    );
});
