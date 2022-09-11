use core::cell::Cell;
use std::cmp::Ordering;

use super::tree::SplayTree;

pub type AuthorID = u8;
pub type SequenceNumber = u64;
pub type OpID = (AuthorID, SequenceNumber);

pub const ROOT_ID: OpID = (0, 0);

pub struct Node<'a, T> {
    // SplayTree fields
    pub(crate) left: Cell<Option<&'a Node<'a, T>>>,
    pub(crate) right: Cell<Option<&'a Node<'a, T>>>,
    pub(crate) origin: Cell<Option<&'a Node<'a, T>>>,

    // CRDT fields
    pub(crate) id: OpID,
    pub(crate) is_deleted: bool,
    pub(crate) content: Option<T>,
}

impl<'a, T> Default for Node<'a, T> {
    #[inline]
    fn default() -> Node<'a, T> {
        Node {
            id: ROOT_ID,
            is_deleted: true,
            content: None,
            left: Cell::new(None),
            right: Cell::new(None),
            origin: Cell::new(None),
        }
    }
}

impl<'a, T> Node<'a, T> {
    pub fn new(
        arena: &'a bumpalo::Bump,
        id: OpID,
        origin: Option<&'a Node<'a, T>>, 
        content: Option<T>,
        tree: &mut SplayTree<'a, T>,
    ) -> &'a Node<'a, T> {
        let node = arena.alloc(Node {
            id,
            is_deleted: false,
            content,
            left: Cell::new(None),
            right: Cell::new(None),
            origin: Cell::new(origin),
        });
        unsafe {
            tree.insert(node);
            node
        }
    }

    pub fn left(&self) -> Option<&'a Node<T>> {
        self.left.get()
    }

    pub fn right(&self) -> Option<&'a Node<T>> {
        self.right.get()
    }

    pub fn origin(&self) -> Option<&'a Node<T>> {
        self.origin.get()
    }

    pub fn author(&self) -> AuthorID {
        self.id.0
    }

    pub fn sequence_num(&self) -> SequenceNumber {
        self.id.1
    }

    pub fn is_deleted(&self) -> bool {
        self.is_deleted
    }

    // In-order traversal
    pub(crate) fn traverse_collect(&'a self, vec: &mut Vec<&'a T>) {
        if let Some(left) = self.left.get() {
            left.traverse_collect(vec);
        }

        if !self.is_deleted && self.content.is_some() {
            vec.push(self.content.as_ref().unwrap())
        }

        if let Some(right) = self.right.get() {
            right.traverse_collect(vec);
        }
    }
}

pub trait NodeComparable<'a, T> {
    fn compare_to_node(&self, other: &'a Node<'a, T>) -> Ordering;
}

impl<T> PartialEq for Node<'_, T> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl<T> Eq for Node<'_, T> {}

impl<T> PartialOrd for Node<'_, T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a, T> Ord for Node<'a, T> {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.id == other.id {
            return Ordering::Equal;
        }

        // if index of our parent is > than the index of other parent, we are bigger
        let our_origin = self.origin.get();
        let other_origin = other.origin.get();
        match our_origin.cmp(&other_origin) {
            Ordering::Greater => {
                Ordering::Greater
            },
            Ordering::Less => {
                Ordering::Less
            },
            Ordering::Equal => {
                // parents are equal, is sequence number the same?
                if self.sequence_num() == other.sequence_num() {
                    // tie break on author id
                    self.author().cmp(&other.author())
                } else {
                    // if sequence number is not > or == then it must be <
                    Ordering::Less
                }
            }
        }
    }
}

impl<'a, T> NodeComparable<'a, T> for Node<'a, T> {
    fn compare_to_node(&self, other: &'a Node<'a, T>) -> Ordering {
        self.cmp(other)
    }
}

