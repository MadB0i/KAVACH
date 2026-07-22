#![no_main]

use kavach_policy::load_policy_from_str;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(toml_str) = std::str::from_utf8(data) {
        let _ = load_policy_from_str(toml_str);
    }
});
