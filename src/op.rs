use crate::json_crdt::{Value, JSONOp};
use crate::json_crdt::{CRDTTerminalFrom, IntoCRDTTerminal};
use crate::keypair::lsb_32;
use crate::keypair::sign;
use crate::keypair::AuthorID;
use crate::keypair::SignedDigest;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::ed25519::Ed25519PublicKey;
use fastcrypto::ed25519::Ed25519Signature;
use fastcrypto::traits::ToFromBytes;
use fastcrypto::Verifier;
use sha2::Digest;
use sha2::Sha256;
use std::fmt::Debug;

/// A lamport clock timestamp. Used to track document versions
pub type SequenceNumber = u64;

/// A unique ID for a single [`Op<T>`]
pub type OpID = [u8; 32];
pub const ROOT_ID: OpID = [0u8; 32];

/// Part of a path to get to a specific CRDT in a nested CRDT
#[derive(Clone, Debug)]
pub enum PathSegment {
    Field(String),
    Index(OpID),
}

pub fn print_path(path: Vec<PathSegment>) -> String {
    path.iter()
        .map(|p| match p {
            PathSegment::Field(s) => s.to_string(),
            PathSegment::Index(i) => lsb_32(*i).to_string(),
        })
        .collect::<Vec<_>>()
        .join(".")
}

pub fn join_path(path: Vec<PathSegment>, segment: PathSegment) -> Vec<PathSegment> {
    let mut p = path;
    p.push(segment);
    p
}

pub fn parse_field(path: Vec<PathSegment>) -> Option<String> {
    if let PathSegment::Field(key) = path.last().unwrap() {
        Some(key.to_string())
    } else {
        None
    }
}

/// Represents a single node in a CRDT
#[derive(Debug, Clone)]
pub struct Op<T>
where
    T: Hashable + Clone,
{
    // Main content of the operation
    // Pre-image of hash
    pub origin: OpID,
    pub author: AuthorID, // pub key of author
    pub seq: SequenceNumber,
    pub content: Option<T>,
    pub path: Vec<PathSegment>, // path to get to target CRDT
    pub is_deleted: bool,

    // Fields that are used to detect faults/tampering
    // This operation is valid iff
    // 1) hashing the preimage gives us the id of the operation
    // 2) we can verify the signed_digest was signed using the pub key of the author
    pub id: OpID,                    // hash of the operation
    pub signed_digest: SignedDigest, // signed hash using priv key of author
}

pub trait Hashable {
    fn hash(&self) -> String;
}

impl<T> Hashable for T
where
    T: Debug,
{
    fn hash(&self) -> String {
        format!("{self:?}")
    }
}


impl<T> Op<T>
where
    T: Hashable + Clone + Into<Value>,
{
    /// Exports a specific op to be JSON generic
    pub fn export(self) -> JSONOp {
        JSONOp::from(self)
    }
}

impl<T> Op<T>
where
    T: Hashable + Clone,
{
    pub fn author(&self) -> AuthorID {
        self.author
    }

    pub fn sequence_num(&self) -> SequenceNumber {
        self.seq
    }

    pub fn into<'a, U: Hashable + Clone + CRDTTerminalFrom<'a, T>>(
        self,
        keypair: &'a Ed25519KeyPair,
        path: Vec<PathSegment>,
    ) -> Op<U> {
        Op {
            content: self.content.and_then(|c| c.into_terminal(keypair, path)),
            origin: self.origin,
            author: self.author,
            seq: self.seq,
            path: self.path,
            is_deleted: self.is_deleted,
            id: self.id,
            signed_digest: self.signed_digest,
        }
    }

    pub fn new(
        origin: OpID,
        author: AuthorID,
        seq: SequenceNumber,
        is_deleted: bool,
        content: Option<T>,
        path: Vec<PathSegment>,
        keypair: &Ed25519KeyPair,
    ) -> Op<T> {
        let mut op = Self {
            origin,
            id: ROOT_ID,
            author,
            signed_digest: [0u8; 64],
            seq,
            is_deleted,
            content,
            path,
        };
        op.id = op.hash();
        op.signed_digest = sign(keypair, &op.id).sig.to_bytes();
        op
    }

    pub fn hash(&self) -> OpID {
        let content_str = match self.content.as_ref() {
            Some(content) => content.hash(),
            None => "".to_string(),
        };
        let fmt_str = format!(
            "{:?},{:?},{:?},{:?},{content_str},{:?}",
            self.origin, self.author, self.seq, self.is_deleted, self.path,
        );
        let mut hasher = Sha256::new();
        hasher.update(fmt_str.as_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result[..]);
        bytes
    }

    pub fn is_valid(&self) -> bool {
        // make sure content is only none for deletion events
        if self.content.is_none() && !self.is_deleted {
            return false;
        }

        // try to avoid expensive sig check if early fail
        if self.hash() != self.id {
            return false;
        }

        // see if digest was actually signed by the author it claims to be signed by
        let digest = Ed25519Signature::from_bytes(&self.signed_digest);
        let pubkey = Ed25519PublicKey::from_bytes(&self.author);
        match (digest, pubkey) {
            (Ok(digest), Ok(pubkey)) => pubkey.verify(&self.id, &digest).is_ok(),
            (_, _) => false,
        }
    }

    /// Special constructor for defining the sentinel root node
    pub fn make_root() -> Op<T> {
        Self {
            origin: ROOT_ID,
            id: ROOT_ID,
            author: [0u8; 32],
            signed_digest: [0u8; 64],
            seq: 0,
            is_deleted: false,
            content: None,
            path: vec![],
        }
    }
}
