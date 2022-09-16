use core::cell::Cell;
use std::{cmp::Ordering, fmt::Display};

use crate::splay::debug::display_op;

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

impl<'a, T> Node<'a, T>
where
    T: Display,
{
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
        tree.insert(node);
        node
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
    pub(crate) fn traverse_collect(&'a self, vec: &mut Vec<&'a Node<'a, T>>) {
        if let Some(left) = self.left.get() {
            left.traverse_collect(vec);
        }

        if !self.is_deleted && self.content.is_some() {
            vec.push(self)
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

impl<T> Eq for Node<'_, T> where T: Display {}

impl<T> PartialOrd for Node<'_, T>
where
    T: Display,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a, T> Ord for Node<'a, T>
where
    T: Display,
{
    // effectively how RGA works:
    // 1. Build the tree, connecting each item to its parent
    // 2. When an item has multiple children, sort them
    //   a) by origin (we want to insert after the right causal parent)
    //   b) by inverted sequence_num (things inserted later come earlier)
    //   c) by author (all else equal, tie break on author for determinism)
    fn cmp(&self, other: &Self) -> Ordering {
        if self.id == other.id {
            return Ordering::Equal;
        }

        // if index of our parent is > than the index of other parent, we are bigger
        let our_origin = self.origin.get();
        let other_origin = other.origin.get();
        match our_origin.cmp(&other_origin) {
            Ordering::Greater => Ordering::Greater,
            Ordering::Equal => {
                // parents are equal, try to break on inverted sequence number
                match other.sequence_num().cmp(&self.sequence_num()) {
                    Ordering::Greater => Ordering::Greater,
                    Ordering::Equal => self.author().cmp(&other.author()),
                    Ordering::Less => Ordering::Less,
                }
            }
            Ordering::Less => Ordering::Less,
        }
    }
}

impl<'a, T> NodeComparable<'a, T> for Node<'a, T>
where
    T: Display,
{
    fn compare_to_node(&self, other: &'a Node<'a, T>) -> Ordering {
        let res = self.cmp(other);
        println!("Comparison check: {} {:?} {}", display_op(self.id), res, display_op(other.id));
        res
    }
}
