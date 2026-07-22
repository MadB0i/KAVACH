#![no_main]

use kavach_mcp::protocol::parse_message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(json_str) = std::str::from_utf8(data) {
        let _ = parse_message(json_str);
    }
});
