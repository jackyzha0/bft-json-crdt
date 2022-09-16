use crate::splay::{
    debug::{display_author, display_op},
    node::{AuthorID, Node, OpID, SequenceNumber, ROOT_ID},
    tree::SplayTree,
};
use std::{cmp::max, collections::BTreeMap, fmt::Display};

pub struct ListCRDT<'a, T>
where
    T: Clone + Display,
{
    our_id: AuthorID,
    splaytree: SplayTree<'a, T>,
    id_to_ref: BTreeMap<OpID, &'a Node<'a, T>>,
    size: usize,

    // TODO: abstract these into a CRDTManager struct or something so we
    // don't duplicate this storage for nested CRDTs later
    //
    /// K: ID that has not arrived
    /// V: Vec of Ops that are waiting on message K
    message_q: BTreeMap<OpID, Vec<Op<T>>>,
    logical_clocks: BTreeMap<AuthorID, SequenceNumber>,
    arena_ref: &'a bumpalo::Bump,
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
    pub fn author(&self) -> AuthorID {
        self.id.0
    }

    pub fn sequence_num(&self) -> SequenceNumber {
        self.id.1
    }
}

impl<'a, T> ListCRDT<'a, T>
where
    T: Eq + Clone + Display,
{
    pub fn new(arena_ref: &'a bumpalo::Bump, id: AuthorID) -> ListCRDT<'a, T> {
        let mut splaytree = SplayTree::default();
        let mut id_to_ref = BTreeMap::new();
        let root_node = Node::new(arena_ref, ROOT_ID, None, None, &mut splaytree);
        id_to_ref.insert(ROOT_ID, root_node);
        let mut logical_clocks = BTreeMap::new();
        logical_clocks.insert(id, 0);
        ListCRDT {
            our_id: id,
            arena_ref,
            id_to_ref,
            splaytree,
            message_q: BTreeMap::new(),
            logical_clocks,
            size: 0,
        }
    }

    pub fn sequence_num(&self) -> SequenceNumber {
        *self.logical_clocks.get(&self.our_id).unwrap()
    }

    fn get_sequence_number(&mut self, id: AuthorID) -> SequenceNumber {
        let val = self.logical_clocks.entry(id).or_insert(0);
        *val
    }

    fn update_sequence_num(&mut self, id: AuthorID, new_seq: SequenceNumber) {
        let new_seq_num = max(self.get_sequence_number(id), new_seq);
        self.logical_clocks.insert(id, new_seq_num);
    }

    pub fn insert(&mut self, after: OpID, content: T) -> Op<T> {
        let id = (self.our_id, self.sequence_num() + 1);
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
        // TODO(1): actually implement delete
        todo!();
    }

    pub fn apply(&mut self, op: Op<T>) {
        let new_seq_num = op.sequence_num();
        let origin = self.id_to_ref.get(&op.origin).copied();

        // we haven't received the causal parent of this operation yet, queue this it up for later
        if origin.is_none() {
            self.message_q
                .entry(op.origin)
                .or_insert(Vec::new())
                .push(op);
            return;
        }

        // TODO(1): check elt_is_deleted to handle delete case properly
        println!(
            "{} Performing an insert of {}: '{}' after {}",
            display_author(self.our_id),
            display_op(op.id),
            op.content.as_ref().unwrap(),
            display_op(op.origin)
        );
        let new_node = Node::new(
            self.arena_ref,
            op.id,
            origin,
            op.content,
            &mut self.splaytree,
        );
        self.id_to_ref.insert(op.id, new_node);
        self.update_sequence_num(self.our_id, new_seq_num);
        println!("{}", self.splaytree.print(Some(op.id)));
        if !op.is_deleted {
            self.size += 1;
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

    pub fn print(&self) -> String {
        self.splaytree.print(None)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        list_crdt::{ListCRDT, Op, OpID},
        splay::node::{AuthorID, ROOT_ID},
    };
    use rand::{rngs::ThreadRng, seq::SliceRandom, Rng};

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
        list2.apply(_1_x);
        list1.apply(_2_y);
        list1.apply(_2_d);

        assert_eq!(list1.traverse_collect(), vec![&'d', &'a', &'b', &'y', &'x']);
        assert_eq!(list1.traverse_collect(), list2.traverse_collect());
    }

    fn random_op<T: Clone>(arr: &Vec<Op<T>>, rng: &mut ThreadRng) -> OpID {
        arr.choose(rng).map(|op| op.id).unwrap_or(ROOT_ID)
    }

    #[test]
    fn test_fuzz_commutative_property() {
        let n: usize = 1;
        let mut rng = rand::thread_rng();
        for _ in 0..n {
            let arena = bumpalo::Bump::new();
            let mut op_log = Vec::<Op<char>>::new();
            let auth1: AuthorID = rng.gen();
            let auth2: AuthorID = rng.gen();
            let mut l1 = ListCRDT::<char>::new(&arena, auth1);
            let mut l2 = ListCRDT::<char>::new(&arena, auth2);
            let mut chk = ListCRDT::<char>::new(&arena, rng.gen());
            for _ in 0..rng.gen_range(4..5) {
                let letter1: char = rng.gen_range(b'a'..b'z') as char;
                let letter2: char = rng.gen_range(b'a'..b'z') as char;
                let op1 = l1.insert(random_op(&op_log, &mut rng), letter1);
                let op2 = l2.insert(random_op(&op_log, &mut rng), letter2);
                op_log.push(op1);
                op_log.push(op2);
            }

            // shuffle ops
            op_log.shuffle(&mut rng);

            // apply to each other
            for op in op_log {
                if op.author() == auth1 {
                    l2.apply(op)
                } else if op.author() == auth2 {
                    l1.apply(op)
                }
                chk.apply(op)
            }

            // ensure all equal
            let l1_doc = l1.traverse_collect();
            let l2_doc = l2.traverse_collect();
            let chk_doc = chk.traverse_collect();
            assert_eq!(l1_doc, l2_doc);
            assert_eq!(l1_doc, chk_doc);
            assert_eq!(l2_doc, chk_doc);
        }
    }
}
