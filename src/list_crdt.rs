use crate::{
    json_crdt::{IntoCRDTTerminal, CRDT},
    keypair::AuthorID,
    op::*,
};
use std::{
    cmp::{max, Ordering},
    collections::HashMap,
    fmt::Debug,
    ops::{Index, IndexMut},
};

#[derive(Clone)]
pub struct ListCRDT<T>
where
    T: Hashable + Clone,
{
    /// List of all the operations we know of
    pub(crate) ops: Vec<Op<T>>,

    /// Public key for this node
    pub our_id: AuthorID,

    /// Path to this CRDT
    pub path: Vec<PathSegment>,

    /// Queue of messages where K is the ID of the message yet to arrive
    /// and V is the list of operations depending on it
    message_q: HashMap<OpID, Vec<Op<T>>>,

    /// Keeps track of the latest document version we know for each peer
    logical_clocks: HashMap<AuthorID, SequenceNumber>,

    /// Highest document version we've seen
    highest_seq: SequenceNumber,
}

impl<T> ListCRDT<T>
where
    T: Hashable + Clone,
{
    /// Create a new List CRDT with the given AuthorID.
    /// AuthorID should be unique.
    pub fn new(id: AuthorID, path: Vec<PathSegment>) -> ListCRDT<T> {
        // initialize other fields
        let ops = vec![Op::make_root()];
        let mut logical_clocks = HashMap::new();
        logical_clocks.insert(id, 0);
        ListCRDT {
            our_id: id,
            path,
            ops,
            message_q: HashMap::new(),
            logical_clocks,
            highest_seq: 0,
        }
    }

    /// Get our own sequence number
    pub fn our_seq(&self) -> SequenceNumber {
        *self.logical_clocks.get(&self.our_id).unwrap()
    }

    /// Locally insert some content causally after the given operation
    pub fn insert<U: IntoCRDTTerminal<T> + Hashable + Clone>(
        &mut self,
        after: OpID,
        content: U,
    ) -> Op<T> {
        // first, make an op that has no path
        // we need to know the op ID before adding a path segment for the subelement
        let transmuted: T = content.clone().into_terminal(self.our_id, vec![]).unwrap();
        let mut op = Op::new(
            after,
            self.our_id,
            self.our_seq() + 1,
            false,
            Some(transmuted),
            self.path.to_owned(),
        );
        let new_id = op.id;
        let new_path = join_path(self.path.to_owned(), PathSegment::Index(new_id));
        let transmuted_updated_path = content.into_terminal(self.our_id, new_path.clone()).unwrap();
        op.content = Some(transmuted_updated_path);
        op.path = new_path;
        self.apply(op.clone());
        op
    }

    /// Shorthand function to insert at index locally
    pub fn insert_idx<U: IntoCRDTTerminal<T> + Hashable + Clone>(
        &mut self,
        idx: usize,
        content: U,
    ) -> Op<T> {
        let mut i = 0;
        for op in &self.ops {
            if !op.is_deleted {
                if idx == i {
                    return self.insert(op.id, content);
                }
                i += 1;
            }
        }
        panic!("index {idx} out of range (length of {i})")
    }

    /// Mark a node as deleted. Will panic if the node doesn't exist
    pub fn delete(&mut self, id: OpID) -> Op<T> {
        let op = Op::new(
            id,
            self.our_id,
            self.our_seq() + 1,
            true,
            None,
            join_path(self.path.to_owned(), PathSegment::Index(id)),
        );
        self.apply(op.clone());
        op
    }

    /// Find the idx of an operation with the given [`OpID`]
    pub fn find_idx(&self, id: OpID) -> Option<usize> {
        self.ops.iter().position(|op| op.id == id)
    }

    /// Apply an operation (both local and remote) to this local list CRDT.
    /// Does a bit of bookkeeping on struct variables like updating logical clocks, etc.
    pub fn apply(&mut self, op: Op<T>) {
        if !op.is_valid_hash() {
            return;
        }

        let op_id = op.id;
        let author = op.author();
        let seq = op.sequence_num();
        let origin_id = self.find_idx(op.origin);

        // we haven't received the causal parent of this operation yet, queue this it up for later
        if origin_id.is_none() {
            self.message_q.entry(op.origin).or_default().push(op);
            return;
        }

        // integrate operation locally and update bookkeeping
        self.log_apply(&op);
        self.integrate(op, origin_id.unwrap());

        // update sequence number for sender and for ourselves
        self.logical_clocks.insert(author, seq);
        self.highest_seq = max(self.highest_seq, seq);
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
    fn integrate(&mut self, new_op: Op<T>, new_op_parent_idx: usize) {
        // if its a delete operation, we don't need to do much
        if new_op.is_deleted {
            let mut op = &mut self.ops[new_op_parent_idx];
            op.is_deleted = true;
            return;
        }

        // start looking from right after parent
        // stop when we reach end of document
        let mut i = new_op_parent_idx + 1;
        while i < self.ops.len() {
            let op = &self.ops[i];
            let op_parent_idx = self.find_idx(op.origin).unwrap();

            // idempotency
            if op.id == new_op.id {
                return;
            }

            // first, lets compare causal origins
            match new_op_parent_idx.cmp(&op_parent_idx) {
                Ordering::Greater => break,
                Ordering::Equal => {
                    // our parents our equal, we are siblings
                    // siblings are sorted first by sequence number then by author id
                    match new_op.sequence_num().cmp(&op.sequence_num()) {
                        Ordering::Greater => break,
                        Ordering::Equal => {
                            // conflict, resolve arbitrarily but deterministically
                            // tie-break on author id as that is unique
                            if new_op.author() > op.author() {
                                break;
                            }
                        }
                        Ordering::Less => (),
                    }
                }
                Ordering::Less => (),
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
    pub fn view(&self) -> Vec<T> {
        self.iter().map(|i| i.to_owned()).collect()
    }
}

impl<T> Debug for ListCRDT<T>
where
    T: Hashable + Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}]",
            self.ops
                .iter()
                .map(|op| format!("{:?}", op.id))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

impl<T> Index<usize> for ListCRDT<T>
where
    T: Hashable + Clone,
{
    type Output = T;
    fn index(&self, idx: usize) -> &Self::Output {
        let mut i = 0;
        for op in &self.ops {
            if !op.is_deleted && op.content.is_some() {
                if idx == i {
                    return op.content.as_ref().unwrap();
                }
                i += 1;
            }
        }
        panic!("index {idx} out of range (length of {i})")
    }
}

impl<T> IndexMut<usize> for ListCRDT<T>
where
    T: Hashable + Clone,
{
    fn index_mut(&mut self, idx: usize) -> &mut Self::Output {
        let mut i = 0;
        for op in &mut self.ops {
            if !op.is_deleted && op.content.is_some() {
                if idx == i {
                    return op.content.as_mut().unwrap();
                }
                i += 1;
            }
        }
        panic!("index {idx} out of range (length of {i})")
    }
}

impl<T> CRDT for ListCRDT<T>
where
    T: Hashable + Clone,
{
    type Inner = T;
    type View = Vec<T>;
    fn apply(&mut self, op: Op<Self::Inner>) {
        self.apply(op)
    }

    fn view(&self) -> Self::View {
        self.view()
    }

    fn new(id: AuthorID, path: Vec<PathSegment>) -> Self {
        Self::new(id, path)
    }
}

#[cfg(feature = "logging-base")]
use crate::debug::DebugView;
#[cfg(feature = "logging-base")]
impl<T> DebugView for ListCRDT<T>
where
    T: Hashable + Clone + DebugView,
{
    fn debug_view(&self, indent: usize) -> String {
        let spacing = " ".repeat(indent);
        let path_str = print_path(self.path.clone());
        let inner = self
            .ops
            .iter()
            .map(|op| {
                format!(
                    "{spacing}{}: {}",
                    &print_hex(&op.id)[..6],
                    op.debug_view(indent)
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        format!("List CRDT @ /{path_str}\n{inner}")
    }
}

#[cfg(test)]
mod test {
    use crate::{keypair::make_author, list_crdt::ListCRDT, op::ROOT_ID};

    #[test]
    fn test_list_simple() {
        let mut list = ListCRDT::<i32>::new(make_author(1), vec![]);
        let _one = list.insert(ROOT_ID, 1);
        let _two = list.insert(_one.id, 2);
        let _three = list.insert(_two.id, 3);
        let _four = list.insert(_one.id, 4);
        assert_eq!(list.view(), vec![1, 4, 2, 3]);
    }

    #[test]
    fn test_list_idempotence() {
        let mut list = ListCRDT::<i32>::new(make_author(1), vec![]);
        let op = list.insert(ROOT_ID, 1);
        for _ in 1..10 {
            list.apply(op.clone());
        }
        assert_eq!(list.view(), vec![1]);
    }

    #[test]
    fn test_list_delete() {
        let mut list = ListCRDT::<char>::new(make_author(1), vec![]);
        let _one = list.insert(ROOT_ID, 'a');
        let _two = list.insert(_one.id, 'b');
        let _three = list.insert(ROOT_ID, 'c');
        list.delete(_one.id);
        list.delete(_two.id);
        assert_eq!(list.view(), vec!['c']);
    }

    #[test]
    fn test_list_interweave_chars() {
        let mut list = ListCRDT::<char>::new(make_author(1), vec![]);
        let _one = list.insert(ROOT_ID, 'a');
        let _two = list.insert(_one.id, 'b');
        let _three = list.insert(ROOT_ID, 'c');
        assert_eq!(list.view(), vec!['c', 'a', 'b']);
    }

    #[test]
    fn test_list_conflicting_agents() {
        let mut list1 = ListCRDT::<char>::new(make_author(1), vec![]);
        let mut list2 = ListCRDT::new(make_author(2), vec![]);
        let _1_a = list1.insert(ROOT_ID, 'a');
        list2.apply(_1_a.clone());
        let _2_b = list2.insert(_1_a.id, 'b');
        list1.apply(_2_b.clone());

        let _2_d = list2.insert(ROOT_ID, 'd');
        let _2_y = list2.insert(_2_b.id, 'y');
        let _1_x = list1.insert(_2_b.id, 'x');

        // create artificial delay, then apply out of order
        list2.apply(_1_x);
        list1.apply(_2_y);
        list1.apply(_2_d);

        assert_eq!(list1.view(), vec!['d', 'a', 'b', 'y', 'x']);
        assert_eq!(list1.view(), list2.view());
    }

    #[test]
    fn test_list_delete_multiple_agent() {
        let mut list1 = ListCRDT::<char>::new(make_author(1), vec![]);
        let mut list2 = ListCRDT::new(make_author(2), vec![]);
        let _1_a = list1.insert(ROOT_ID, 'a');
        list2.apply(_1_a.clone());
        let _2_b = list2.insert(_1_a.id, 'b');
        let del_1_a = list1.delete(_1_a.id);
        list1.apply(_2_b);
        list2.apply(del_1_a);

        assert_eq!(list1.view(), vec!['b']);
        assert_eq!(list1.view(), list2.view());
    }

    #[test]
    fn test_list_nested() {
        let mut list1 = ListCRDT::<char>::new(make_author(1), vec![]);
        let _c = list1.insert(ROOT_ID, 'c');
        let _a = list1.insert(ROOT_ID, 'a');
        let _d = list1.insert(_c.id, 'd');
        let _b = list1.insert(_a.id, 'b');

        assert_eq!(list1.view(), vec!['a', 'b', 'c', 'd']);
    }
}
