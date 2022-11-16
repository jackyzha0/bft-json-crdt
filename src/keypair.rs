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

/// Represents the ID of a unique node. An Ed25519 public key
pub type AuthorID = [u8; ED25519_PUBLIC_KEY_LENGTH];

/// A signed message
pub type SignedDigest = [u8; ED25519_SIGNATURE_LENGTH];

/// Create a fake public key from a u8
pub fn make_author(n: u8) -> AuthorID {
    let mut id = [0u8; ED25519_PUBLIC_KEY_LENGTH];
    id[0] = n;
    id
}

/// Get the least significant 32 bits of a public key
pub fn lsb_32(pubkey: AuthorID) -> u32 {
    ((pubkey[0] as u32) << 24)
        + ((pubkey[1] as u32) << 16)
        + ((pubkey[2] as u32) << 8)
        + (pubkey[3] as u32)
}

/// SHA256 hash of a string
pub fn sha256(input: String) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result[..]);
    bytes
}

/// Generate a random Ed25519 keypair from OS rng
pub fn make_keypair() -> Ed25519KeyPair {
    let mut csprng = OsRng {};
    Ed25519KeyPair::generate(&mut csprng)
}

/// Sign a byte array
pub fn sign(keypair: &Ed25519KeyPair, message: &[u8]) -> Ed25519Signature {
    keypair.sign(message)
}

/// Verify a byte array was signed by the given pubkey
pub fn verify(pubkey: Ed25519PublicKey, message: &[u8], signature: Ed25519Signature) -> bool {
    pubkey.verify(message, &signature).is_ok()
}
