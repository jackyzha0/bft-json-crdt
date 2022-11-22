use crate::debug::DebugView;
use crate::json_crdt::{CrdtNode, OpState, Value};
use crate::op::{join_path, print_path, Op, PathSegment, SequenceNumber};
use std::cmp::{max, Ordering};
use std::fmt::Debug;

use crate::keypair::AuthorId;

/// A simple delete-wins, last-writer-wins (LWW) register CRDT.
/// Basically only for adding support for primitives within a more complex CRDT
#[derive(Clone)]
pub struct LwwRegisterCrdt<T>
where
    T: CrdtNode,
{
    /// Public key for this node
    pub our_id: AuthorId,
    /// Path to this CRDT
    pub path: Vec<PathSegment>,
    /// Internal value of this CRDT. We wrap it in an Op to retain the author/sequence metadata
    value: Op<T>,
    /// The sequence number of this node
    our_seq: SequenceNumber,
}

impl<T> LwwRegisterCrdt<T>
where
    T: CrdtNode,
{
    /// Create a new register CRDT with the given [`AuthorID`] (it should be unique)
    pub fn new(id: AuthorId, path: Vec<PathSegment>) -> LwwRegisterCrdt<T> {
        LwwRegisterCrdt {
            our_id: id,
            path,
            value: Op::make_root(),
            our_seq: 0,
        }
    }

    /// Sets the current value of the register
    pub fn set<U: Into<Value>>(&mut self, content: U) -> Op<Value> {
        let mut op = Op::new(
            self.value.id,
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

    /// Apply an operation (both local and remote) to this local register CRDT.
    pub fn apply(&mut self, op: Op<Value>) -> OpState {
        if !op.is_valid_hash() {
            return OpState::ErrHashMismatch;
        }

        let op: Op<T> = op.into();
        let seq = op.sequence_num();

        // take most recent update by sequence number
        match seq.cmp(&self.our_seq) {
            Ordering::Greater => {
                self.value = Op {
                    id: self.value.id,
                    ..op
                };
            }
            Ordering::Equal => {
                // if we are equal, tie break on author
                if op.author() < self.value.author() {
                    // we want to keep id constant so replace everything but id
                    self.value = Op {
                        id: self.value.id,
                        ..op
                    };
                }
            }
            Ordering::Less => {} // LWW, ignore if its outdate
        };

        // update bookkeeping
        self.our_seq = max(self.our_seq, seq);
        OpState::Ok
    }

    fn view(&self) -> Option<T> {
        self.value.content.to_owned()
    }
}

impl<T> CrdtNode for LwwRegisterCrdt<T>
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

impl<T> DebugView for LwwRegisterCrdt<T>
where
    T: CrdtNode + DebugView,
{
    fn debug_view(&self, indent: usize) -> String {
        let spacing = " ".repeat(indent);
        let path_str = print_path(self.path.clone());
        let inner = self.value.debug_view(indent + 2);
        format!("LWW Register CRDT @ /{path_str}\n{spacing}{inner}")
    }
}

impl<T> Debug for LwwRegisterCrdt<T>
where
    T: CrdtNode,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.value.id)
    }
}

#[cfg(test)]
mod test {
    use super::LwwRegisterCrdt;
    use crate::{json_crdt::OpState, keypair::make_author};

    #[test]
    fn test_lww_simple() {
        let mut register = LwwRegisterCrdt::new(make_author(1), vec![]);
        assert_eq!(register.view(), None);
        register.set(1);
        assert_eq!(register.view(), Some(1));
        register.set(99);
        assert_eq!(register.view(), Some(99));
    }

    #[test]
    fn test_lww_multiple_writer() {
        let mut register1 = LwwRegisterCrdt::new(make_author(1), vec![]);
        let mut register2 = LwwRegisterCrdt::new(make_author(2), vec![]);
        let _a = register1.set('a');
        let _b = register1.set('b');
        let _c = register2.set('c');
        assert_eq!(register2.view(), Some('c'));
        assert_eq!(register1.apply(_c), OpState::Ok);
        assert_eq!(register2.apply(_b), OpState::Ok);
        assert_eq!(register2.apply(_a), OpState::Ok);
        assert_eq!(register1.view(), Some('b'));
        assert_eq!(register2.view(), Some('b'));
    }

    #[test]
    fn test_lww_idempotence() {
        let mut register = LwwRegisterCrdt::new(make_author(1), vec![]);
        let op = register.set(1);
        for _ in 1..10 {
            assert_eq!(register.apply(op.clone()), OpState::Ok);
        }
        assert_eq!(register.view(), Some(1));
    }

    #[test]
    fn test_lww_consistent_tiebreak() {
        let mut register1 = LwwRegisterCrdt::new(make_author(1), vec![]);
        let mut register2 = LwwRegisterCrdt::new(make_author(2), vec![]);
        let _a = register1.set('a');
        let _b = register2.set('b');
        assert_eq!(register1.apply(_b), OpState::Ok);
        assert_eq!(register2.apply(_a), OpState::Ok);
        let _c = register1.set('c');
        let _d = register2.set('d');
        assert_eq!(register2.apply(_c), OpState::Ok);
        assert_eq!(register1.apply(_d), OpState::Ok);
        assert_eq!(register1.view(), register2.view());
        assert_eq!(register1.view(), Some('c'));
    }
}
