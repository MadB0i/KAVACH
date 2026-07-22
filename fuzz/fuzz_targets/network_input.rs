#![no_main]

use kavach_core::resource::{NetworkHost, NetworkResource, NetworkScheme};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = NetworkHost::new(s);
        let _ = NetworkScheme::new(s);
        let _ = NetworkResource::new(
            NetworkScheme::new("http").unwrap_or(NetworkScheme::new("https").unwrap()),
            NetworkHost::new("127.0.0.1").unwrap_or(NetworkHost::new("localhost").unwrap()),
            None,
            if s.is_empty() { "/" } else { s },
        );
    }
});
