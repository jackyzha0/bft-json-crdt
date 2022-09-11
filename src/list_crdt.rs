use crate::splay::{
    node::{AuthorID, Node, OpID, SequenceNumber, ROOT_ID},
    tree::SplayTree,
};
use std::cmp::max;

pub struct ListCRDT<'a, T> {
    our_id: AuthorID,
    arena_ref: &'a bumpalo::Bump,
    splaytree: SplayTree<'a, T>,
    highest_sequence_number: SequenceNumber,
    size: usize,
}

pub struct Op<T> {
    pub(crate) origin: OpID,
    pub(crate) id: OpID,
    pub(crate) is_deleted: bool,
    pub(crate) content: Option<T>,
}

impl<T> Op<T> {
    pub fn sequence_num(&self) -> SequenceNumber {
        self.id.1
    }
}

impl<'a, T> ListCRDT<'a, T>
where
    T: Eq,
{
    pub fn new(arena_ref: &'a bumpalo::Bump, id: AuthorID) -> ListCRDT<'a, T> {
        let mut splaytree = SplayTree::default();
        Node::new(&arena_ref, ROOT_ID, None, &mut splaytree);
        ListCRDT {
            our_id: id,
            arena_ref,
            splaytree,
            highest_sequence_number: 0,
            size: 0,
        }
    }

    pub fn insert(&mut self, after: OpID, content: T) -> OpID {
        let id = (self.our_id, self.highest_sequence_number + 1);
        self.apply(Op {
            id,
            origin: after,
            is_deleted: false,
            content: Some(content),
        });
        id
    }

    pub fn apply(&mut self, op: Op<T>) {
        let elt_seq_num = op.sequence_num();
        let elt_is_deleted = op.is_deleted;
        unsafe {
            let origin = self.splaytree.find(&op.origin);
            Node::new(self.arena_ref, op.id, op.content, &mut self.splaytree);
        }

        self.highest_sequence_number = max(elt_seq_num, self.highest_sequence_number);
        if !elt_is_deleted {
            self.size += 1;
        }
    }

    pub fn traverse_collect(&self) -> Vec<&T> {
        self.splaytree.traverse_collect()
    }
}

#[cfg(test)]
mod test {
    use crate::{splay::node::ROOT_ID, list_crdt::ListCRDT};


    #[test]
    fn test_simple() {
        let arena = bumpalo::Bump::new();
        let mut list = ListCRDT::new(&arena, 1);
        let _one = list.insert(ROOT_ID, 1);
        let _two = list.insert(_one, 3);
        let _three = list.insert(_two, 2);
        assert_eq!(list.traverse_collect(), vec![&1, &3, &2]);
    }
}
