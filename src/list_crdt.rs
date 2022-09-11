use crate::splay::{
    node::{AuthorID, Node, OpID, SequenceNumber, ROOT_ID},
    tree::SplayTree,
};
use std::{cmp::max, collections::BTreeMap};

pub struct ListCRDT<'a, T>
where
    T: Clone,
{
    our_id: AuthorID,
    arena_ref: &'a bumpalo::Bump,
    splaytree: SplayTree<'a, T>,
    id_to_ref: BTreeMap<OpID, &'a Node<'a, T>>,
    highest_sequence_number: SequenceNumber,
    size: usize,
    /// key: IDs that we are missing, value: vec of Ops that are
    /// waiting on it
    message_q: BTreeMap<OpID, Vec<Op<T>>>,
}

#[derive(Clone, Copy)]
pub struct Op<T>
where
    T: Clone,
{
    pub(crate) origin: OpID,
    pub(crate) id: OpID,
    pub(crate) is_deleted: bool,
    pub(crate) content: Option<T>,
}

impl<T> Op<T>
where
    T: Clone,
{
    pub fn sequence_num(&self) -> SequenceNumber {
        self.id.1
    }
}

impl<'a, T> ListCRDT<'a, T>
where
    T: Eq + Clone,
{
    pub fn new(arena_ref: &'a bumpalo::Bump, id: AuthorID) -> ListCRDT<'a, T> {
        let mut splaytree = SplayTree::default();
        let mut id_to_ref = BTreeMap::new();
        let root_node = Node::new(arena_ref, ROOT_ID, None, None, &mut splaytree);
        id_to_ref.insert(ROOT_ID, root_node);
        ListCRDT {
            our_id: id,
            arena_ref,
            id_to_ref,
            splaytree,
            message_q: BTreeMap::new(),
            highest_sequence_number: 0,
            size: 0,
        }
    }

    pub fn insert(&mut self, after: OpID, content: T) -> Op<T> {
        let id = (self.our_id, self.highest_sequence_number + 1);
        let op = Op {
            id,
            origin: after,
            is_deleted: false,
            content: Some(content),
        };
        self.apply(op.clone());
        op
    }

    pub fn delete(&mut self, id: OpID) {
        todo!();
    }

    pub fn apply(&mut self, op: Op<T>) {
        let new_seq_num = op.sequence_num();
        let origin = self.id_to_ref.get(&op.origin).copied();

        // we haven't received the causal parent of this operation yet, queue this it up for later
        if origin.is_none() {
            println!("haven't received message, queueing for later");
            self.message_q.entry(op.origin).or_insert(Vec::new()).push(op); 
            return;
        }

        // TODO(2): check elt_is_deleted to handle delete case properly
        let new_node = Node::new(
            self.arena_ref,
            op.id,
            origin,
            op.content,
            &mut self.splaytree,
        );
        self.id_to_ref.insert(op.id, new_node);
        self.highest_sequence_number = max(new_seq_num, self.highest_sequence_number);
        if !op.is_deleted {
            self.size += 1;
        } else {
            self.size -= 1;
        }

        // apply all of its causal dependents if there are any
        let dependent_queue = self.message_q.remove(&op.id);
        if let Some(mut q) = dependent_queue {
            for dependent in q.drain(..) {
                self.apply(dependent);
            }
        }
    }

    pub fn traverse_collect(&self) -> Vec<&T> {
        self.splaytree.traverse_collect()
    }
}

#[cfg(test)]
mod test {
    use crate::{list_crdt::ListCRDT, splay::node::ROOT_ID};

    #[test]
    fn test_simple() {
        let arena = bumpalo::Bump::new();
        let mut list = ListCRDT::new(&arena, 1);
        let _one = list.insert(ROOT_ID, 1);
        let _two = list.insert(_one.id, 2);
        let _three = list.insert(_two.id, 3);
        let _four = list.insert(_one.id, 4);
        assert_eq!(list.traverse_collect(), vec![&1, &4, &2, &3]);
    }

    #[test]
    fn test_interweave_chars() {
        let arena = bumpalo::Bump::new();
        let mut list = ListCRDT::new(&arena, 1);
        let _one = list.insert(ROOT_ID, 'a');
        let _two = list.insert(_one.id, 'b');
        let _three = list.insert(ROOT_ID, 'c');
        assert_eq!(list.traverse_collect(), vec![&'c', &'a', &'b']);
    }

    #[test]
    fn test_conflicting_agents() {
        let arena = bumpalo::Bump::new();
        let mut list1 = ListCRDT::new(&arena, 1);
        let mut list2 = ListCRDT::new(&arena, 2);
        let _1_a = list1.insert(ROOT_ID, 'a');
        list2.apply(_1_a);
        let _2_b = list2.insert(_1_a.id, 'b');
        list1.apply(_2_b);

        let _2_d = list2.insert(ROOT_ID, 'd');
        let _2_y = list2.insert(_2_b.id, 'y');
        let _1_x = list1.insert(_2_b.id, 'x');

        // create artificial delay, then apply out of order
        list1.apply(_2_y);
        list1.apply(_2_d);
        list2.apply(_1_x);
        assert_eq!(list1.traverse_collect(), vec![&'d', &'a', &'b', &'y', &'x']);
        // this is failing because of TODO(1)
        assert_eq!(list1.traverse_collect(), list2.traverse_collect());
    }
}
