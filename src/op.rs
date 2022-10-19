use sha2::Digest;
use sha2::Sha256;
use std::fmt::{format, Display};

/// Represents the ID of a unique node
pub type AuthorID = u64;

/// A lamport clock timestamp. Used to track document versions
pub type SequenceNumber = u64;

/// A unique ID for a single [`Op<T>`]
pub type OpID = [u8; 32];
pub const ROOT_ID: OpID = [0u8; 32];

/// Represents a single node in the List CRDT
#[derive(Clone, Copy)]
pub struct Op<T>
where
    T: Clone,
{
    pub origin: OpID,
    pub id: OpID,
    pub author: AuthorID,
    pub seq: SequenceNumber,
    pub is_deleted: bool,
    pub content: Option<T>,
}

impl<T> Op<T>
where
    T: Clone + Display,
{
    pub fn author(&self) -> AuthorID {
        self.author
    }

    pub fn sequence_num(&self) -> SequenceNumber {
        self.seq
    }

    pub fn new(origin: OpID, author: AuthorID, seq: SequenceNumber, is_deleted: bool, content: T) -> Op<T> {
        let mut op = Self {
            origin,
            id: ROOT_ID,
            author,
            seq,
            is_deleted,
            content: Some(content),
        };
        op.id = op.hash();
        op
    }

    pub fn hash(&self) -> OpID {
        let fmt_str = format!(
            "{:?},{:?},{:?},{}",
            self.origin,
            self.author,
            self.seq,
            self.content.as_ref().unwrap()
        );
        let mut hasher = Sha256::new();
        hasher.update(fmt_str.as_bytes());
        let result = hasher.finalize();
        let mut bytes: [u8; 32] = Default::default();
        bytes.copy_from_slice(&result[..]);
        bytes
    }

    /// Special constructor for defining the sentinel root node
    pub fn make_root() -> Op<T> {
        Self {
            origin: ROOT_ID,
            id: ROOT_ID,
            author: 0,
            seq: 0,
            is_deleted: false,
            content: None,
        }
    }
}
