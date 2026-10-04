#![no_main]

use bleep_rpc::{parse_mint_request, parse_stake_request, parse_tx_request, parse_unstake_request};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_tx_request(data);
    let _ = parse_mint_request(data);
    let _ = parse_stake_request(data);
    let _ = parse_unstake_request(data);
});
