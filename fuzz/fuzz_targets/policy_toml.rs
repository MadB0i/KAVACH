#![no_main]

use libfuzzer_sys::fuzz_target;
use kavach_policy::load_policy_from_str;

fuzz_target!(|data: &[u8]| {
    if let Ok(toml_str) = std::str::from_utf8(data) {
        let _ = load_policy_from_str(toml_str);
    }
});
