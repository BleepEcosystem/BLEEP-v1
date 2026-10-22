#![no_main]

use bleep_p2p::SecureMessage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ =
        bincode::serde::decode_from_slice::<SecureMessage, _>(data, bincode::config::standard());
    let _ = serde_json::from_slice::<SecureMessage>(data);
});
