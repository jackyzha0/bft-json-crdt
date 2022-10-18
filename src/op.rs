/// Represents the ID of a unique node
pub type AuthorID = u64;

/// A lamport clock timestamp. Used to track document versions
pub type SequenceNumber = u64;

/// A unique ID for a single [`Op<T>`]
pub type OpID = (AuthorID, SequenceNumber);
pub const ROOT_ID: OpID = (0, 0);

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
    T: Clone,
{
    pub fn author(&self) -> AuthorID {
        self.author
    }

    pub fn sequence_num(&self) -> SequenceNumber {
        self.seq
    }

    /// Special constructor for defining the sentinel root node
    pub fn make_root() -> Op<T> {
        Self {
            origin: ROOT_ID,
            id: ROOT_ID,
            author: ROOT_ID.0,
            seq: ROOT_ID.1,
            is_deleted: false,
            content: None,
        }
    }
}
