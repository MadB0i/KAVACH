#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(json_str) = std::str::from_utf8(data) {
        // Fuzz JSON-RPC 2.0 message parsing
        let _ = serde_json::from_str::<serde_json::Value>(json_str)
            .map(|v| v.get("method").and_then(|m| m.as_str()));
    }
});
