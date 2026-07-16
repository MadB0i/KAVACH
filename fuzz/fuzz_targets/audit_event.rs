#![no_main]

use libfuzzer_sys::fuzz_target;
use kavach_audit::event::AuditEventRecord;

fuzz_target!(|data: &[u8]| {
    if let Ok(json_str) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<AuditEventRecord>(json_str);
    }
});
