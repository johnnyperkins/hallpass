#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| hallpassd::fuzz::netlink(data));
