pub use fastcrypto::{
    ed25519::{
        Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature, ED25519_PUBLIC_KEY_LENGTH,
        ED25519_SIGNATURE_LENGTH,
    },
    traits::{KeyPair, Signer},
    Verifier,
};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};

/// Represents the ID of a unique node
pub type AuthorID = [u8; ED25519_PUBLIC_KEY_LENGTH];
pub type SignedDigest = [u8; ED25519_SIGNATURE_LENGTH];

pub fn make_author(n: u8) -> AuthorID {
    let mut id = [0u8; ED25519_PUBLIC_KEY_LENGTH];
    id[0] = n;
    id
}

pub fn lsb_32(pubkey: AuthorID) -> u32 {
    ((pubkey[0] as u32) << 24)
        + ((pubkey[1] as u32) << 16)
        + ((pubkey[2] as u32) << 8)
        + (pubkey[3] as u32)
}

pub fn sha256(input: String) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result[..]);
    bytes
}

pub fn make_keypair() -> Ed25519KeyPair {
    let mut csprng = OsRng {};
    Ed25519KeyPair::generate(&mut csprng)
}

pub fn sign(keypair: &Ed25519KeyPair, message: &[u8]) -> Ed25519Signature {
    keypair.sign(message)
}

pub fn verify(pubkey: Ed25519PublicKey, message: &[u8], signature: Ed25519Signature) -> bool {
    pubkey.verify(message, &signature).is_ok()
}
