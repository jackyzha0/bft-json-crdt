use crate::{
    debug::debug_path_mismatch,
    json_crdt::{CrdtNode, OpState, Value},
    keypair::AuthorId,
    op::*,
};
use std::{
    cmp::{max, Ordering},
    collections::HashMap,
    fmt::Debug,
    ops::{Index, IndexMut},
};

/// An RGA-like list CRDT that can store a CRDT-like datatype
#[derive(Clone)]
pub struct ListCrdt<T>
where
    T: CrdtNode,
{
    /// Public key for this node
    pub our_id: AuthorId,
    /// Path to this CRDT
    pub path: Vec<PathSegment>,
    /// List of all the operations we know of
    pub ops: Vec<Op<T>>,
    /// Queue of messages where K is the ID of the message yet to arrive
    /// and V is the list of operations depending on it
    message_q: HashMap<OpId, Vec<Op<T>>>,
    /// The sequence number of this node
    our_seq: SequenceNumber,
}

impl<T> ListCrdt<T>
where
    T: CrdtNode,
{
    /// Create a new List CRDT with the given [`AuthorID`] (it should be unique)
    pub fn new(id: AuthorId, path: Vec<PathSegment>) -> ListCrdt<T> {
        let ops = vec![Op::make_root()];
        ListCrdt {
            our_id: id,
            path,
            ops,
            message_q: HashMap::new(),
            our_seq: 0,
        }
    }

    /// Locally insert some content causally after the given operation
    pub fn insert<U: Into<Value>>(&mut self, after: OpId, content: U) -> Op<Value> {
        let mut op = Op::new(
            after,
            self.our_id,
            self.our_seq + 1,
            false,
            Some(content.into()),
            self.path.to_owned(),
        );

        // we need to know the op ID before setting the path as [`PathSegment::Index`] requires an
        // [`OpID`]
        let new_path = join_path(self.path.to_owned(), PathSegment::Index(op.id));
        op.path = new_path;
        self.apply(op.clone());
        op
    }

    /// Shorthand function to insert at index locally. Indexing ignores deleted items
    pub fn insert_idx<U: Into<Value> + Clone>(&mut self, idx: usize, content: U) -> Op<Value> {
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

    /// Shorthand to figure out the OpID of something with a given index.
    /// Useful for declaring a causal dependency if you didn't create the original
    pub fn id_at(&self, idx: usize) -> Option<OpId> {
        let mut i = 0;
        for op in &self.ops {
            if !op.is_deleted {
                if idx == i {
                    return Some(op.id);
                }
                i += 1;
            }
        }
        None
    }

    /// Mark a node as deleted. If the node doesn't exist, it will be stuck
    /// waiting for that node to be created.
    pub fn delete(&mut self, id: OpId) -> Op<Value> {
        let op = Op::new(
            id,
            self.our_id,
            self.our_seq + 1,
            true,
            None,
            join_path(self.path.to_owned(), PathSegment::Index(id)),
        );
        self.apply(op.clone());
        op
    }

    /// Find the idx of an operation with the given [`OpID`]
    pub fn find_idx(&self, id: OpId) -> Option<usize> {
        self.ops.iter().position(|op| op.id == id)
    }

    /// Apply an operation (both local and remote) to this local list CRDT.
    /// Forwards it to a nested CRDT if necessary.
    pub fn apply(&mut self, op: Op<Value>) -> OpState {
        if !op.is_valid_hash() {
            return OpState::ErrHashMismatch;
        }

        if !ensure_subpath(&self.path, &op.path) {
            return OpState::ErrPathMismatch;
        }

        // haven't reached end yet, navigate to inner CRDT
        if op.path.len() - 1 > self.path.len() {
            if let Some(PathSegment::Index(op_id)) = op.path.get(self.path.len()) {
                let op_id = op_id.to_owned();
                if let Some(idx) = self.find_idx(op_id) {
                    if self.ops[idx].content.is_none() {
                        return OpState::ErrListApplyToEmpty;
                    } else {
                        return self.ops[idx].content.as_mut().unwrap().apply(op);
                    }
                } else {
                    debug_path_mismatch(
                        join_path(self.path.to_owned(), PathSegment::Index(op_id)),
                        op.path,
                    );
                    return OpState::ErrPathMismatch;
                };
            } else {
                debug_path_mismatch(self.path.to_owned(), op.path);
                return OpState::ErrPathMismatch;
            }
        }

        // otherwise, this is just a direct replacement
        self.integrate(op.into())
    }

    /// Main CRDT logic of integrating an op properly into our local log
    /// without causing conflicts. This is basically a really fancy
    /// insertion sort.
    ///
    /// Effectively, we
    /// 1) find the parent item
    /// 2) find the right spot to insert before the next node
    fn integrate(&mut self, new_op: Op<T>) -> OpState {
        let op_id = new_op.id;
        let seq = new_op.sequence_num();
        let origin_id = self.find_idx(new_op.origin);

        if origin_id.is_none() {
            self.message_q
                .entry(new_op.origin)
                .or_default()
                .push(new_op);
            return OpState::MissingCausalDependencies;
        }

        let new_op_parent_idx = origin_id.unwrap();

        // if its a delete operation, we don't need to do much
        self.log_apply(&new_op);
        if new_op.is_deleted {
            let op = &mut self.ops[new_op_parent_idx];
            op.is_deleted = true;
            return OpState::Ok;
        }

        // otherwise, we are in an insert case
        // start looking from right after parent
        // stop when we reach end of document
        let mut i = new_op_parent_idx + 1;
        while i < self.ops.len() {
            let op = &self.ops[i];
            let op_parent_idx = self.find_idx(op.origin).unwrap();

            // idempotency
            if op.id == new_op.id {
                return OpState::Ok;
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
        self.our_seq = max(self.our_seq, seq);
        self.log_ops(Some(op_id));

        // apply all of its causal dependents if there are any
        let dependent_queue = self.message_q.remove(&op_id);
        if let Some(mut q) = dependent_queue {
            for dependent in q.drain(..) {
                self.integrate(dependent);
            }
        }
        OpState::Ok
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

impl<T> Debug for ListCrdt<T>
where
    T: CrdtNode,
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

/// Allows us to index into a List CRDT like we would with an array
impl<T> Index<usize> for ListCrdt<T>
where
    T: CrdtNode,
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

/// Allows us to mutably index into a List CRDT like we would with an array
impl<T> IndexMut<usize> for ListCrdt<T>
where
    T: CrdtNode,
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

impl<T> CrdtNode for ListCrdt<T>
where
    T: CrdtNode,
{
    fn apply(&mut self, op: Op<Value>) -> OpState {
        self.apply(op.into())
    }

    fn view(&self) -> Value {
        self.view().into()
    }

    fn new(id: AuthorId, path: Vec<PathSegment>) -> Self {
        Self::new(id, path)
    }
}

#[cfg(feature = "logging-base")]
use crate::debug::DebugView;
#[cfg(feature = "logging-base")]
impl<T> DebugView for ListCrdt<T>
where
    T: CrdtNode + DebugView,
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
    use crate::{json_crdt::OpState, keypair::make_author, list_crdt::ListCrdt, op::ROOT_ID};

    #[test]
    fn test_list_simple() {
        let mut list = ListCrdt::<i64>::new(make_author(1), vec![]);
        let _one = list.insert(ROOT_ID, 1);
        let _two = list.insert(_one.id, 2);
        let _three = list.insert(_two.id, 3);
        let _four = list.insert(_one.id, 4);
        assert_eq!(list.view(), vec![1, 4, 2, 3]);
    }

    #[test]
    fn test_list_idempotence() {
        let mut list = ListCrdt::<i64>::new(make_author(1), vec![]);
        let op = list.insert(ROOT_ID, 1);
        for _ in 1..10 {
            assert_eq!(list.apply(op.clone()), OpState::Ok);
        }
        assert_eq!(list.view(), vec![1]);
    }

    #[test]
    fn test_list_delete() {
        let mut list = ListCrdt::<char>::new(make_author(1), vec![]);
        let _one = list.insert(ROOT_ID, 'a');
        let _two = list.insert(_one.id, 'b');
        let _three = list.insert(ROOT_ID, 'c');
        list.delete(_one.id);
        list.delete(_two.id);
        assert_eq!(list.view(), vec!['c']);
    }

    #[test]
    fn test_list_interweave_chars() {
        let mut list = ListCrdt::<char>::new(make_author(1), vec![]);
        let _one = list.insert(ROOT_ID, 'a');
        let _two = list.insert(_one.id, 'b');
        let _three = list.insert(ROOT_ID, 'c');
        assert_eq!(list.view(), vec!['c', 'a', 'b']);
    }

    #[test]
    fn test_list_conflicting_agents() {
        let mut list1 = ListCrdt::<char>::new(make_author(1), vec![]);
        let mut list2 = ListCrdt::new(make_author(2), vec![]);
        let _1_a = list1.insert(ROOT_ID, 'a');
        assert_eq!(list2.apply(_1_a.clone()), OpState::Ok);
        let _2_b = list2.insert(_1_a.id, 'b');
        assert_eq!(list1.apply(_2_b.clone()), OpState::Ok);

        let _2_d = list2.insert(ROOT_ID, 'd');
        let _2_y = list2.insert(_2_b.id, 'y');
        let _1_x = list1.insert(_2_b.id, 'x');

        // create artificial delay, then apply out of order
        assert_eq!(list2.apply(_1_x), OpState::Ok);
        assert_eq!(list1.apply(_2_y), OpState::Ok);
        assert_eq!(list1.apply(_2_d), OpState::Ok);

        assert_eq!(list1.view(), vec!['d', 'a', 'b', 'y', 'x']);
        assert_eq!(list1.view(), list2.view());
    }

    #[test]
    fn test_list_delete_multiple_agent() {
        let mut list1 = ListCrdt::<char>::new(make_author(1), vec![]);
        let mut list2 = ListCrdt::new(make_author(2), vec![]);
        let _1_a = list1.insert(ROOT_ID, 'a');
        assert_eq!(list2.apply(_1_a.clone()), OpState::Ok);
        let _2_b = list2.insert(_1_a.id, 'b');
        let del_1_a = list1.delete(_1_a.id);
        assert_eq!(list1.apply(_2_b), OpState::Ok);
        assert_eq!(list2.apply(del_1_a), OpState::Ok);

        assert_eq!(list1.view(), vec!['b']);
        assert_eq!(list1.view(), list2.view());
    }

    #[test]
    fn test_list_nested() {
        let mut list1 = ListCrdt::<char>::new(make_author(1), vec![]);
        let _c = list1.insert(ROOT_ID, 'c');
        let _a = list1.insert(ROOT_ID, 'a');
        let _d = list1.insert(_c.id, 'd');
        let _b = list1.insert(_a.id, 'b');

        assert_eq!(list1.view(), vec!['a', 'b', 'c', 'd']);
    }
}
