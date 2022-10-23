use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use rand::rngs::OsRng;

/// Represents the ID of a unique node
pub type AuthorID = [u8; PUBLIC_KEY_LENGTH];
pub type SignedDigest = [u8; SIGNATURE_LENGTH];

pub fn lsb_32(pubkey: AuthorID) -> u32 {
    ((pubkey[0] as u32) << 24)
        + ((pubkey[1] as u32) << 16)
        + ((pubkey[2] as u32) << 8)
        + ((pubkey[3] as u32) << 0)
}

pub fn make_keypair() -> Keypair {
    let mut csprng = OsRng {};
    Keypair::generate(&mut csprng)
}

pub fn sign(keypair: &Keypair, message: &[u8]) -> Signature {
    keypair.sign(message)
}

pub fn verify(pubkey: PublicKey, message: &[u8], signature: Signature) -> bool {
    pubkey.verify(message, &signature).is_ok()
}
