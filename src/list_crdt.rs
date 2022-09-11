use crate::splay::{
    node::{AuthorID, Node, OpID, SequenceNumber, ROOT_ID},
    tree::SplayTree,
};
use std::{cmp::max, collections::BTreeMap};

pub struct ListCRDT<'a, T> {
    our_id: AuthorID,
    arena_ref: &'a bumpalo::Bump,
    splaytree: SplayTree<'a, T>,
    id_to_ref: BTreeMap<OpID, &'a Node<'a, T>>,
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
        let mut id_to_ref = BTreeMap::new();
        let root_node = Node::new(&arena_ref, ROOT_ID, None, None, &mut splaytree);
        id_to_ref.insert(ROOT_ID, root_node);
        ListCRDT {
            our_id: id,
            arena_ref,
            id_to_ref,
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
        let origin = self.id_to_ref.get(&op.origin).map(|origin| *origin);
        let new_node = Node::new(self.arena_ref, op.id, origin, op.content, &mut self.splaytree);
        self.id_to_ref.insert(op.origin, new_node);
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
        let _two = list.insert(_one, 2);
        let _three = list.insert(_two, 3);
        let _two = list.insert(_one, 4);
        assert_eq!(list.traverse_collect(), vec![&1, &4, &2, &3]);
    }
    
    #[test]
    fn test_interweave_chars() {
        let arena = bumpalo::Bump::new();
        let mut list = ListCRDT::new(&arena, 1);
        let _one = list.insert(ROOT_ID, 'a');
        let _two = list.insert(_one, 'b');
        let _three = list.insert(ROOT_ID, 'c');
        assert_eq!(list.traverse_collect(), vec![&'c', &'a', &'b']);
    }
}
