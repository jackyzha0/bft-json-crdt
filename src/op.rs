use crate::debug::debug_path_mismatch;
use crate::json_crdt::{CRDTNode, CRDTNodeFromValue, IntoCRDTNode, SignedOp, Value};
use crate::keypair::{sha256, AuthorID};
use fastcrypto::ed25519::Ed25519KeyPair;
use std::fmt::Debug;

/// A lamport clock timestamp. Used to track document versions
pub type SequenceNumber = u64;

/// A unique ID for a single [`Op<T>`]
pub type OpID = [u8; 32];
pub const ROOT_ID: OpID = [0u8; 32];
/// Part of a path to get to a specific CRDT in a nested CRDT
#[derive(Clone, Debug, PartialEq)]
pub enum PathSegment {
    Field(String),
    Index(OpID),
}

pub fn print_hex<const N: usize>(bytes: &[u8; N]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

pub fn print_path(path: Vec<PathSegment>) -> String {
    path.iter()
        .map(|p| match p {
            PathSegment::Field(s) => s.to_string(),
            PathSegment::Index(i) => print_hex(i)[..6].to_string(),
        })
        .collect::<Vec<_>>()
        .join(".")
}

pub fn ensure_subpath(our_path: &Vec<PathSegment>, op_path: &Vec<PathSegment>) -> bool {
    if our_path.len() > op_path.len() {
        debug_path_mismatch(our_path.to_owned(), op_path.to_owned());
        return false;
    }
    for i in 0..our_path.len() {
        let ours = our_path.get(i);
        let theirs = op_path.get(i);
        if ours != theirs {
            debug_path_mismatch(our_path.to_owned(), op_path.to_owned());
            return false;
        }
    }
    true
}

pub fn join_path(path: Vec<PathSegment>, segment: PathSegment) -> Vec<PathSegment> {
    let mut p = path;
    p.push(segment);
    p
}

pub fn parse_field(path: Vec<PathSegment>) -> Option<String> {
    path.last().and_then(|segment| {
        if let PathSegment::Field(key) = segment {
            Some(key.to_string())
        } else {
            None
        }
    })
}

/// Represents a single node in a CRDT
#[derive(Clone)]
pub struct Op<T>
where
    T: CRDTNode,
{
    pub origin: OpID,
    pub author: AuthorID, // pub key of author
    pub seq: SequenceNumber,
    pub content: Option<T>,
    pub path: Vec<PathSegment>, // path to get to target CRDT
    pub is_deleted: bool,
    pub id: OpID, // hash of the operation
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

impl Op<Value> {
    pub fn into<T: CRDTNodeFromValue + CRDTNode>(self) -> Op<T> {
        // TODO instead of doing ok(), unwrap inner error and report it
        Op {
            content: self
                .content
                .and_then(|c| c.into_node(self.id, self.path.clone()).ok()),
            origin: self.origin,
            author: self.author,
            seq: self.seq,
            path: self.path,
            is_deleted: self.is_deleted,
            id: self.id,
        }
    }
}

impl<T> Op<T>
where
    T: CRDTNode,
{
    /// Exports a specific op to be JSON generic
    pub fn sign(self, keypair: &Ed25519KeyPair) -> SignedOp {
        SignedOp::from_op(self, keypair, vec![])
    }

    /// Exports a specific op to be JSON generic
    pub fn sign_with_dependencies(
        self,
        keypair: &Ed25519KeyPair,
        dependencies: Vec<&SignedOp>,
    ) -> SignedOp {
        SignedOp::from_op(
            self,
            keypair,
            dependencies
                .iter()
                .map(|dep| dep.signed_digest)
                .collect::<Vec<_>>(),
        )
    }

    pub fn author(&self) -> AuthorID {
        self.author
    }

    pub fn sequence_num(&self) -> SequenceNumber {
        self.seq
    }

    pub fn new(
        origin: OpID,
        author: AuthorID,
        seq: SequenceNumber,
        is_deleted: bool,
        content: Option<T>,
        path: Vec<PathSegment>,
    ) -> Op<T> {
        let mut op = Self {
            origin,
            id: ROOT_ID,
            author,
            seq,
            is_deleted,
            content,
            path,
        };
        op.id = op.hash_to_id();
        op
    }

    pub fn hash_to_id(&self) -> OpID {
        let content_str = match self.content.as_ref() {
            Some(content) => content.hash(),
            None => "".to_string(),
        };
        let fmt_str = format!(
            "{:?},{:?},{:?},{:?},{content_str}",
            self.origin, self.author, self.seq, self.is_deleted,
        );
        sha256(fmt_str)
    }

    pub fn is_valid_hash(&self) -> bool {
        // make sure content is only none for deletion events
        if self.content.is_none() && !self.is_deleted {
            return false;
        }

        // try to avoid expensive sig check if early fail
        let res = self.hash_to_id() == self.id;
        if !res {
            self.debug_hash_failure();
        }
        res
    }

    /// Special constructor for defining the sentinel root node
    pub fn make_root() -> Op<T> {
        Self {
            origin: ROOT_ID,
            id: ROOT_ID,
            author: [0u8; 32],
            seq: 0,
            is_deleted: false,
            content: None,
            path: vec![],
        }
    }
}
