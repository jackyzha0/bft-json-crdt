use crate::op::*;
use std::{
    cmp::{max, Ordering},
    collections::BTreeMap,
    fmt::Display,
};

pub struct ListCRDT<T>
where
    T: Clone + Display,
{
    /// Our unique ID
    pub our_id: AuthorID,

    /// List of all the operations we know of
    pub(crate) ops: Vec<Op<T>>,

    /// Queue of messages where K is the ID of the message yet to arrive
    /// and V is the list of operations depending on it
    message_q: BTreeMap<OpID, Vec<Op<T>>>,

    /// Keeps track of the latest document version we know for each peer
    logical_clocks: BTreeMap<AuthorID, SequenceNumber>,

    /// Highest document version we've seen
    highest_seq: SequenceNumber,
}

impl<T> ListCRDT<T>
where
    T: Eq + Display + Clone,
{
    /// Create a new List CRDT with the given AuthorID.
    /// AuthorID should be unique.
    pub fn new(id: AuthorID) -> ListCRDT<T> {
        let mut ops = Vec::new();
        ops.push(Op::make_root());
        let mut logical_clocks = BTreeMap::new();
        logical_clocks.insert(id, 0);
        ListCRDT {
            our_id: id,
            ops,
            message_q: BTreeMap::new(),
            logical_clocks,
            highest_seq: 0,
        }
    }

    /// Get our own sequence number
    pub fn our_seq(&self) -> SequenceNumber {
        *self.logical_clocks.get(&self.our_id).unwrap()
    }

    /// Locally insert some content causally after the given operation
    pub fn insert(&mut self, after: OpID, content: T) -> Op<T> {
        let id = (self.our_id, self.our_seq() + 1);
        let op = Op {
            id,
            seq: self.highest_seq + 1,
            origin: after,
            is_deleted: false,
            content: Some(content),
        };
        self.apply(op.clone());
        op
    }

    /// Mark a node as deleted. Will panic if the node doesn't exist
    pub fn delete(&mut self, id: OpID) -> Op<T> {
        let idx = self.find(id).unwrap();
        let mut op = self.ops[idx].clone();
        op.is_deleted = true;
        self.apply(op.clone());
        op
    }

    /// Find the idx of an operation with the given [`OpID`]
    pub(crate) fn find(&self, id: OpID) -> Option<usize> {
        self.ops.iter().position(|op| op.id == id)
    }

    /// Apply an operation (both local and remote) to this local list CRDT.
    /// Does a bit of bookkeeping on struct variables like updating logical clocks, etc.
    pub fn apply(&mut self, op: Op<T>) {
        let op_id = op.id;
        let (agent, agent_seq) = op_id;
        let global_seq = op.sequence_num();
        let origin_id = self.find(op.origin);

        // we haven't received the causal parent of this operation yet, queue this it up for later
        if origin_id.is_none() {
            self.message_q
                .entry(op.origin)
                .or_insert(Vec::new())
                .push(op);
            return;
        }

        // integrate operation locally and update bookkeeping
        self.log_apply(&op);
        self.integrate(op);

        // update sequence number for sender
        self.logical_clocks.insert(agent, agent_seq);

        // update our id
        self.highest_seq = max(self.highest_seq, global_seq);
        self.logical_clocks.insert(self.our_id, self.highest_seq);

        // log result
        self.log_ops(Some(op_id));

        // apply all of its causal dependents if there are any
        let dependent_queue = self.message_q.remove(&op_id);
        if let Some(mut q) = dependent_queue {
            for dependent in q.drain(..) {
                self.apply(dependent);
            }
        }
    }

    /// Main CRDT logic of integrating an op properly into our local log
    /// without causing conflicts. This is basically a really fancy
    /// insertion sort.
    ///
    /// Effectively, we
    /// 1) find the parent item
    /// 2) find the right spot to insert before the next node
    fn integrate(&mut self, new_op: Op<T>) {
        // get index of the new op's origin
        let new_op_parent_idx = self.find(new_op.origin).unwrap();

        // start looking from right after parent
        // stop when we reach end of document
        let mut i = new_op_parent_idx + 1;
        while i < self.ops.len() {
            let op = &self.ops[i];
            let op_parent_idx = self.find(op.origin).unwrap();

            // if we are the same node, just replace (guarantees idempotency)
            if op.id == new_op.id {
                self.ops[i] = new_op;
                return;
            }

            // first, lets compare causal origins
            match new_op_parent_idx.cmp(&op_parent_idx) {
                // if index of our parent > index of other parent, we are bigger (ok to insert)
                Ordering::Greater => break,
                // our parents our equal, we are siblings
                // siblings are sorted first by sequence number then by author id
                Ordering::Equal => {
                    match new_op.sequence_num().cmp(&op.sequence_num()) {
                        Ordering::Greater => break,
                        Ordering::Equal => {
                            // conflict, resolve arbitrarily but deterministically
                            // tie-break on author id as that is unique
                            if new_op.author() < op.author() {
                                break;
                            }
                        }
                        Ordering::Less => {}
                    }
                }
                // our parent is less than theirs,
                Ordering::Less => {}
            }
            i += 1;
        }

        // insert at i
        self.ops.insert(i, new_op);
    }

    /// Make an iterator out of list CRDT contents, ignoring deleted items and empty content
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.ops
            .iter()
            .filter(|op| !op.is_deleted && op.content.is_some())
            .map(|op| op.content.as_ref().unwrap())
    }

    /// Convenience function to get a vector of visible list elements
    pub fn view(&self) -> Vec<&T> {
        self.iter().collect()
    }
}

#[cfg(test)]
mod test {
    use crate::{list_crdt::ListCRDT, op::ROOT_ID};

    #[test]
    fn test_simple() {
        let mut list = ListCRDT::new(1);
        let _one = list.insert(ROOT_ID, 1);
        let _two = list.insert(_one.id, 2);
        let _three = list.insert(_two.id, 3);
        let _four = list.insert(_one.id, 4);
        assert_eq!(list.view(), vec![&1, &4, &2, &3]);
    }

    #[test]
    fn test_idempotence() {
        let mut list = ListCRDT::new(1);
        let op = list.insert(ROOT_ID, 1);
        for _ in 1..10 {
            list.apply(op);
        }
        assert_eq!(list.view(), vec![&1]);
    }

    #[test]
    fn test_delete() {
        let mut list = ListCRDT::new(1);
        let _one = list.insert(ROOT_ID, 'a');
        let _two = list.insert(_one.id, 'b');
        let _three = list.insert(ROOT_ID, 'c');
        list.delete(_one.id);
        list.delete(_two.id);
        assert_eq!(list.view(), vec![&'c']);
    }

    #[test]
    fn test_interweave_chars() {
        let mut list = ListCRDT::new(1);
        let _one = list.insert(ROOT_ID, 'a');
        let _two = list.insert(_one.id, 'b');
        let _three = list.insert(ROOT_ID, 'c');
        assert_eq!(list.view(), vec![&'c', &'a', &'b']);
    }

    #[test]
    fn test_conflicting_agents() {
        let mut list1 = ListCRDT::new(1);
        let mut list2 = ListCRDT::new(2);
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

        assert_eq!(list1.view(), vec![&'d', &'a', &'b', &'y', &'x']);
        assert_eq!(list1.view(), list2.view());
    }

    #[test]
    fn test_delete_multiple_agent() {
        let mut list1 = ListCRDT::new(1);
        let mut list2 = ListCRDT::new(2);
        let _1_a = list1.insert(ROOT_ID, 'a');
        list2.apply(_1_a);
        let _2_b = list2.insert(_1_a.id, 'b');
        let del_1_a = list1.delete(_1_a.id);
        list1.apply(_2_b);
        list2.apply(del_1_a);

        assert_eq!(list1.view(), vec![&'b']);
        assert_eq!(list1.view(), list2.view());
    }

    #[test]
    fn test_nested() {
        let mut list1 = ListCRDT::new(1);
        let _c = list1.insert(ROOT_ID, 'c');
        let _a = list1.insert(ROOT_ID, 'a');
        let _d = list1.insert(_c.id, 'd');
        let _b = list1.insert(_a.id, 'b');

        assert_eq!(list1.view(), vec![&'a', &'b', &'c', &'d']);
    }
}
