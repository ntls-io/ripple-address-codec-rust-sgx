#![no_std]

#[macro_use]
extern crate sgx_tstd as std;

use std::backtrace;
use std::string::String;
use std::vec::Vec;

use sgx_tunittest::*;

#[path = "../../../tests/api.rs"]
mod api;

#[no_mangle]
pub extern "C" fn run_tests_ecall() -> usize {
    backtrace::enable_backtrace("enclave.signed.so", backtrace::PrintFormat::Short).unwrap();

    rsgx_unit_tests!(
        api::account_id::decode_bad_alphabet,
        api::account_id::decode_bad_lenght,
        api::account_id::decode_bad_prefix,
        api::account_id::decode_bad_checksum,
        api::account_id::encode_random,
        api::account_id::encode,
        api::account_id::decode,
        api::secp256k1_seed::decode_bad_alphabet,
        api::secp256k1_seed::decode_bad_lenght,
        api::secp256k1_seed::decode_bad_prefix,
        api::secp256k1_seed::decode_bad_checksum,
        api::secp256k1_seed::encode_random,
        api::secp256k1_seed::encode,
        api::secp256k1_seed::decode,
        api::ed25519_seed::decode_bad_alphabet,
        api::ed25519_seed::decode_bad_lenght,
        api::ed25519_seed::decode_bad_prefix,
        api::ed25519_seed::decode_bad_checksum,
        api::ed25519_seed::encode_random,
        api::ed25519_seed::encode,
        api::ed25519_seed::decode,
    )
}
