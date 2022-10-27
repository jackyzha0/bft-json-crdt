use fastcrypto::ed25519::Ed25519KeyPair;
use crate::keypair::make_keypair;

pub struct Document {
    /// Public key for this node
    keypair: Ed25519KeyPair,
}


impl Document {
    pub fn new() -> Document {
        // seed rng and generate keypair
        let keypair = make_keypair();
        Self {
            keypair
        }
    }
}

impl Default for Document {
    fn default() -> Self {
        Self::new()
    }
}
