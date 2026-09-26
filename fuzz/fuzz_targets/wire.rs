#![no_main]

//! Frames off either socket. A control or observe client sends ClientMsg to
//! a root daemon; the daemon's replies are decoded by every client. Whatever
//! decodes must survive a round trip unchanged, or two builds could read one
//! frame as two different requests.

use hallpass_types::wire::{decode, encode, FRAME_PREFIX_BYTES};
use hallpass_types::{ClientMsg, DaemonMsg};

fn round_trip<T>(data: &[u8])
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let Ok(msg) = decode::<T>(data) else {
        return;
    };
    let frame = encode(&msg).expect("a decoded message re-encodes");
    let again: T = decode(&frame[FRAME_PREFIX_BYTES..]).expect("and decodes again");
    assert_eq!(msg, again);
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    round_trip::<ClientMsg>(data);
    round_trip::<DaemonMsg>(data);
});
