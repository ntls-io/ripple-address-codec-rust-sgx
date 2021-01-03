//! Encodes/decodes base58 encoded XRP Ledger identifiers
//!
//! Functions for encoding and decoding XRP Ledger addresses and seeds.
//!
//! # Examples
//!
//! See [Functions][crate#functions] section

#![deny(
    warnings,
    clippy::all,
    missing_debug_implementations,
    missing_copy_implementations,
    missing_docs,
    missing_crate_level_docs,
    missing_doc_code_examples,
    non_ascii_idents,
    unreachable_pub
)]
#![doc(test(attr(deny(warnings))))]
#![doc(html_root_url = "https://docs.rs/ripple-address-codec/0.1.0")]

use std::{convert::TryInto, result};

use base_x;
use ring::digest::{digest, SHA256};

mod error;

pub use self::error::{Error, Error::DecodeError};
pub use self::Algorithm::{Ed25519, Secp256k1};

const ALPHABET: &str = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
const CHECKSUM_LENGTH: usize = 4;
const ENTROPY_LEN: usize = 16;

/// Seed entropy array
///
/// The entropy must be exactly 16 bytes (128 bits).
pub type Entropy = [u8; ENTROPY_LEN];

/// Result with decoding error
pub type Result<T> = result::Result<T, Error>;

/// The elliptic curve digital signature algorithm
/// with which the seed is intended to be used
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// Elliptic Curve Digital Signature Algorithm (ECDSA): secp256k1
    Secp256k1,
    /// Edwards-curve Digital Signature Algorithm (EdDSA): Ed25519
    Ed25519,
}

impl Default for Algorithm {
    fn default() -> Self {
        Self::Secp256k1
    }
}

/// Encode the given entropy as an XRP Ledger seed (secret)
///
/// The entropy must be exactly 16 bytes (128 bits). The encoding
/// includes which elliptic curve digital signature algorithm the
/// seed is intended to be used with. The seed is used to produce
/// the private key.
///
/// # Examples
///
/// ```
/// use ripple_address_codec::{encode_seed, Secp256k1, Ed25519};
///
/// // In the real world you **must** generate random entropy
/// let naive_entropy = [0; 16];
///
/// assert_eq!(encode_seed(&naive_entropy, &Secp256k1), "sp6JS7f14BuwFY8Mw6bTtLKWauoUs");
/// assert_eq!(encode_seed(&naive_entropy, &Ed25519), "sEdSJHS4oiAdz7w2X2ni1gFiqtbJHqE");
/// ```
pub fn encode_seed(entropy: &Entropy, algorithm: &Algorithm) -> String {
    let prefix = match algorithm {
        Secp256k1 => SeedSecP256K1.prefix(),
        Ed25519 => SeedEd25519.prefix(),
    };

    encode_bytes_with_prefix(prefix, entropy)
}

/// Decode a seed into a tuple with seed's entropy bytes and algorithm
///
/// # Examples
///
/// ```
/// use ripple_address_codec::{decode_seed, Secp256k1, Ed25519};
///
/// assert_eq!(decode_seed("sp6JS7f14BuwFY8Mw6bTtLKWauoUs"), Ok(([0; 16], &Secp256k1)));
/// assert_eq!(decode_seed("sEdSJHS4oiAdz7w2X2ni1gFiqtbJHqE"), Ok(([0; 16], &Ed25519)));
/// ```
///
/// # Errors
///
/// Returns [`DecodeError`] if seed is invalid.
pub fn decode_seed(seed: &str) -> Result<(Entropy, &'static Algorithm)> {
    decode_seed_secp256k1(seed).or(decode_seed_ed25519(seed))
}

/// Encode bytes as a classic address (starting with r...)
///
/// # Examples
///
/// ```
/// use ripple_address_codec::encode_account_id;
///
/// assert_eq!(encode_account_id(&[0; 20]), "rrrrrrrrrrrrrrrrrrrrrhoLvTp");
/// ```
pub fn encode_account_id(bytes: &[u8; Address::PAYLOAD_LEN]) -> String {
    encode_bytes_with_prefix(Address.prefix(), bytes)
}

/// Decode a classic address (starting with r...) to its raw bytes
///
/// # Examples
///
/// ```
/// use ripple_address_codec::decode_account_id;
///
/// assert_eq!(decode_account_id("rrrrrrrrrrrrrrrrrrrrrhoLvTp"), Ok([0; 20]));
/// ```
///
/// # Errors
///
/// Returns [`DecodeError`] if account id string is invalid.
pub fn decode_account_id(account_id: &str) -> Result<[u8; Address::PAYLOAD_LEN]> {
    let decoded_bytes = decode_with_xrp_alphabet(account_id)?;

    let payload = get_payload(decoded_bytes, Address)?;

    Ok(payload.try_into().unwrap())
}

trait Settings {
    const PAYLOAD_LEN: usize;
    const PREFIX: &'static [u8] = &[];

    fn prefix(&self) -> &'static [u8] {
        Self::PREFIX
    }

    fn prefix_len(&self) -> usize {
        Self::PREFIX.len()
    }

    fn payload_len(&self) -> usize {
        Self::PAYLOAD_LEN
    }
}

struct Address;

impl Settings for Address {
    const PREFIX: &'static [u8] = &[0x00];
    const PAYLOAD_LEN: usize = 20;
}

struct SeedSecP256K1;

impl SeedSecP256K1 {
    const ALG: Algorithm = Secp256k1;
}

impl Settings for SeedSecP256K1 {
    const PREFIX: &'static [u8] = &[0x21];
    const PAYLOAD_LEN: usize = ENTROPY_LEN;
}

struct SeedEd25519;

impl SeedEd25519 {
    const ALG: Algorithm = Ed25519;
}

impl Settings for SeedEd25519 {
    const PREFIX: &'static [u8] = &[0x01, 0xE1, 0x4B];
    const PAYLOAD_LEN: usize = ENTROPY_LEN;
}

fn decode_seed_secp256k1(s: &str) -> Result<(Entropy, &'static Algorithm)> {
    let decoded_bytes = decode_with_xrp_alphabet(s)?;

    let payload = get_payload(decoded_bytes, SeedSecP256K1)?;

    Ok((payload.try_into().unwrap(), &SeedSecP256K1::ALG))
}

fn decode_seed_ed25519(s: &str) -> Result<(Entropy, &'static Algorithm)> {
    let decoded_bytes = decode_with_xrp_alphabet(s)?;

    let payload = get_payload(decoded_bytes, SeedEd25519)?;

    Ok((payload.try_into().unwrap(), &SeedEd25519::ALG))
}

fn encode_bytes_with_prefix(prefix: &[u8], bytes: &[u8]) -> String {
    encode_bytes(&[prefix, bytes].concat())
}

fn encode_bytes(bytes: &[u8]) -> String {
    let checked_bytes = [bytes, &calc_checksum(bytes)].concat();
    base_x::encode(ALPHABET, &checked_bytes)
}

fn decode_with_xrp_alphabet(s: &str) -> Result<Vec<u8>> {
    Ok(base_x::decode(ALPHABET, s)?)
}

fn get_payload(bytes: Vec<u8>, settings: impl Settings) -> Result<Vec<u8>> {
    verify_payload_len(&bytes, settings.prefix_len(), settings.payload_len())?;
    verify_prefix(settings.prefix(), &bytes)?;
    let checked_bytes = get_checked_bytes(bytes)?;

    Ok(checked_bytes[settings.prefix_len()..].try_into().unwrap())
}

fn verify_prefix(prefix: &[u8], bytes: &[u8]) -> Result<()> {
    if bytes.starts_with(prefix) {
        return Ok(());
    }

    Err(DecodeError)
}

fn verify_payload_len(bytes: &[u8], prefix_len: usize, expected_len: usize) -> Result<()> {
    if bytes[prefix_len..bytes.len() - CHECKSUM_LENGTH].len() == expected_len {
        return Ok(());
    }

    Err(DecodeError)
}

fn get_checked_bytes(mut bytes_with_checksum: Vec<u8>) -> Result<Vec<u8>> {
    verify_checksum_lenght(&bytes_with_checksum)?;

    //Split bytes with checksum to checked bytes and checksum
    let checksum = bytes_with_checksum.split_off(bytes_with_checksum.len() - CHECKSUM_LENGTH);
    let bytes = bytes_with_checksum;

    verify_checksum(&bytes, &checksum)?;

    Ok(bytes)
}

fn verify_checksum(input: &[u8], checksum: &[u8]) -> Result<()> {
    if calc_checksum(input) == checksum {
        Ok(())
    } else {
        Err(DecodeError)
    }
}

fn verify_checksum_lenght(bytes: &[u8]) -> Result<()> {
    let len = bytes.len();

    if len < CHECKSUM_LENGTH + 1 {
        return Err(DecodeError);
    }

    Ok(())
}

fn calc_checksum(bytes: &[u8]) -> [u8; CHECKSUM_LENGTH] {
    sha256_digest(&sha256_digest(bytes))[..CHECKSUM_LENGTH]
        .try_into()
        .unwrap()
}

fn sha256_digest(data: &[u8]) -> Vec<u8> {
    digest(&SHA256, data).as_ref().to_vec()
}
