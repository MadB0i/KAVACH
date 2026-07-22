#![no_main]

use kavach_core::request::ToolRequest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(json_str) = std::str::from_utf8(data) {
        if let Ok(req) = serde_json::from_str::<ToolRequest>(json_str) {
            let _ = req.validate();
        }
        let _ = serde_json::from_str::<ToolRequest>(json_str);
    }
});
