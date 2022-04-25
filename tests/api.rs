use ripple_address_codec as api;

use utils::*;

mod utils {
    use std::prelude::v1::*;

    use std::convert::TryInto;

    use hex;
    use rand::{thread_rng, Rng};

    pub fn to_bytes(hex: &str) -> Vec<u8> {
        hex::decode(hex).unwrap()
    }

    pub fn to_20_bytes(hex: &str) -> [u8; 20] {
        to_bytes(hex).try_into().unwrap()
    }

    pub fn to_16_bytes(hex: &str) -> [u8; 16] {
        to_bytes(hex).try_into().unwrap()
    }

    pub fn to_hex(bytes: &[u8]) -> String {
        hex::encode_upper(bytes)
    }

    pub fn get_20_random_bytes() -> [u8; 20] {
        let mut bytes = [0; 20];

        thread_rng()
            .try_fill(&mut bytes[..])
            .expect("random generator error");

        bytes
    }

    pub fn get_16_random_bytes() -> [u8; 16] {
        let mut bytes = [0; 16];

        thread_rng()
            .try_fill(&mut bytes[..])
            .expect("random generator error");

        bytes
    }
}

pub(crate) mod account_id {
    use super::*;

    // #[test]
    pub(crate) fn decode_bad_alphabet() {
        assert_eq!(
            api::decode_account_id("r_000").unwrap_err(),
            api::DecodeError
        );
    }

    // #[test]
    pub(crate) fn decode_bad_lenght() {
        assert_eq!(
            api::decode_account_id("rJrRMgWyPbY35ErN").unwrap_err(),
            api::DecodeError
        );
    }

    // #[test]
    pub(crate) fn decode_bad_prefix() {
        assert_eq!(
            api::decode_account_id("bJrRMgiRgrU6hDF4pgu5DXQdWyPbY35ErN").unwrap_err(),
            api::DecodeError
        );
    }

    // #[test]
    pub(crate) fn decode_bad_checksum() {
        assert_eq!(
            api::decode_account_id("rJrRMgiRgrU6hDF4pgu5DXQdWyPbY35ErA").unwrap_err(),
            api::DecodeError
        );
    }

    // #[test]
    pub(crate) fn encode_random() {
        let bytes = get_20_random_bytes();
        let encoded = api::encode_account_id(&bytes);
        let decoded_bytes = api::decode_account_id(&encoded).unwrap();

        assert!(encoded.starts_with("r"));

        assert_eq!(bytes, decoded_bytes);
    }

    // #[test]
    pub(crate) fn encode() {
        assert_eq!(
            api::encode_account_id(&to_20_bytes("BA8E78626EE42C41B46D46C3048DF3A1C3C87072")),
            "rJrRMgiRgrU6hDF4pgu5DXQdWyPbY35ErN"
        );
    }

    // #[test]
    pub(crate) fn decode() {
        assert_eq!(
            api::decode_account_id("rJrRMgiRgrU6hDF4pgu5DXQdWyPbY35ErN").unwrap(),
            to_20_bytes("BA8E78626EE42C41B46D46C3048DF3A1C3C87072")
        );
    }
}

pub(crate) mod secp256k1_seed {
    use super::*;

    // #[test]
    pub(crate) fn decode_bad_alphabet() {
        assert_eq!(api::decode_seed("s_000").unwrap_err(), api::DecodeError);
    }

    // #[test]
    pub(crate) fn decode_bad_lenght() {
        assert_eq!(
            api::decode_seed("sn259rEFXrQrWcwV6dfL").unwrap_err(),
            api::DecodeError
        );
    }

    // #[test]
    pub(crate) fn decode_bad_prefix() {
        assert_eq!(
            api::decode_seed("Sn259rEFXrQrWyx3Q7XneWcwV6dfL").unwrap_err(),
            api::DecodeError
        );
    }

    // #[test]
    pub(crate) fn decode_bad_checksum() {
        assert_eq!(
            api::decode_seed("sn259rEFXrQrWyx3Q7XneWcwV6dfA").unwrap_err(),
            api::DecodeError
        );
    }

    // #[test]
    pub(crate) fn encode_random() {
        let bytes = get_16_random_bytes();
        let encoded = api::encode_seed(&bytes, &api::Secp256k1);
        let (decoded_bytes, decoded_kind) = api::decode_seed(&encoded).unwrap();

        assert!(encoded.starts_with("s"));
        assert_eq!(decoded_bytes, bytes);
        assert_eq!(decoded_kind, &api::Secp256k1);
    }

    // #[test]
    pub(crate) fn encode() {
        assert_eq!(
            api::encode_seed(
                &to_16_bytes("CF2DE378FBDD7E2EE87D486DFB5A7BFF"),
                &api::Secp256k1
            ),
            "sn259rEFXrQrWyx3Q7XneWcwV6dfL"
        );
    }

    // #[test]
    pub(crate) fn decode() {
        let (bytes, kind) = api::decode_seed("sn259rEFXrQrWyx3Q7XneWcwV6dfL").unwrap();

        assert_eq!(to_hex(&bytes), "CF2DE378FBDD7E2EE87D486DFB5A7BFF");

        assert_eq!(kind, &api::Secp256k1)
    }
}

pub(crate) mod ed25519_seed {
    use super::*;

    // #[test]
    pub(crate) fn decode_bad_alphabet() {
        assert_eq!(api::decode_seed("sEd_000").unwrap_err(), api::DecodeError);
    }

    // #[test]
    pub(crate) fn decode_bad_lenght() {
        assert_eq!(api::decode_seed("sEdTM1uX8").unwrap_err(), api::DecodeError);
    }

    // #[test]
    pub(crate) fn decode_bad_prefix() {
        assert_eq!(
            api::decode_seed("SEdTM1uX8pu2do5XvTnutH6HsouMaM2").unwrap_err(),
            api::DecodeError
        );
    }

    // #[test]
    pub(crate) fn decode_bad_checksum() {
        assert_eq!(
            api::decode_seed("sEdTM1uX8pu2do5XvTnutH6HsouMaMA").unwrap_err(),
            api::DecodeError
        );
    }

    // #[test]
    pub(crate) fn encode_random() {
        let bytes = get_16_random_bytes();
        let encoded = api::encode_seed(&bytes, &api::Ed25519);
        let (decoded_bytes, decoded_kind) = api::decode_seed(&encoded).unwrap();

        assert!(encoded.starts_with("sEd"));
        assert_eq!(decoded_bytes, bytes);
        assert_eq!(decoded_kind, &api::Ed25519);
    }

    // #[test]
    pub(crate) fn encode() {
        assert_eq!(
            api::encode_seed(
                &to_16_bytes("4C3A1D213FBDFB14C7C28D609469B341"),
                &api::Ed25519
            ),
            "sEdTM1uX8pu2do5XvTnutH6HsouMaM2"
        );
    }

    // #[test]
    pub(crate) fn decode() {
        let (bytes, kind) = api::decode_seed("sEdTM1uX8pu2do5XvTnutH6HsouMaM2").unwrap();

        assert_eq!(to_hex(&bytes), "4C3A1D213FBDFB14C7C28D609469B341");

        assert_eq!(kind, &api::Ed25519)
    }
}
