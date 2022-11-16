use crate::debug::DebugView;
use crate::json_crdt::{CRDTNode, Value, OpState};
use crate::op::{print_path, Op, PathSegment, SequenceNumber, join_path};
use std::cmp::{max, Ordering};
use std::collections::HashMap;
use std::fmt::Debug;

use crate::keypair::AuthorID;

#[derive(Clone)]
pub struct LWWRegisterCRDT<T>
where
    T: CRDTNode,
{
    our_id: AuthorID,
    pub path: Vec<PathSegment>,
    value: Op<T>,
    logical_clocks: HashMap<AuthorID, SequenceNumber>,
    highest_seq: SequenceNumber,
}

impl<T> LWWRegisterCRDT<T>
where
    T: CRDTNode,
{
    pub fn new(id: AuthorID, path: Vec<PathSegment>) -> LWWRegisterCRDT<T> {
        let mut logical_clocks = HashMap::new();
        logical_clocks.insert(id, 0);
        LWWRegisterCRDT {
            our_id: id,
            path,
            value: Op::make_root(),
            logical_clocks,
            highest_seq: 0,
        }
    }

    pub fn our_seq(&self) -> SequenceNumber {
        *self.logical_clocks.get(&self.our_id).unwrap()
    }

    pub fn set<U: Into<Value>>(&mut self, content: U) -> Op<Value> {
        let mut op = Op::new(
            self.value.id,
            self.our_id,
            self.our_seq() + 1,
            false,
            Some(content.into()),
            self.path.to_owned(),
        );
        let new_id = op.id;
        let new_path = join_path(self.path.to_owned(), PathSegment::Index(new_id));
        op.path = new_path;
        self.apply(op.clone());
        op
    }

    pub fn apply(&mut self, op: Op<Value>) -> OpState {
        if !op.is_valid_hash() {
            return OpState::ErrHashMismatch;
        }

        let op: Op<T> = op.into();
        let author = op.author();
        let seq = op.sequence_num();

        // take most recent update by sequence number
        match seq.cmp(&self.our_seq()) {
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
        self.logical_clocks.insert(author, seq);
        self.highest_seq = max(self.highest_seq, seq);
        self.logical_clocks.insert(self.our_id, self.highest_seq);
        OpState::Ok
    }

    fn view(&self) -> Option<T> {
        self.value.content.to_owned()
    }
}

impl<T> CRDTNode for LWWRegisterCRDT<T>
where
    T: CRDTNode,
{
    fn apply(&mut self, op: Op<Value>) -> OpState {
        self.apply(op.into())
    }

    fn view(&self) -> Value {
        self.view().into()
    }

    fn new(id: AuthorID, path: Vec<PathSegment>) -> Self {
        Self::new(id, path)
    }
}

impl<T> DebugView for LWWRegisterCRDT<T>
where
    T: CRDTNode + DebugView,
{
    fn debug_view(&self, indent: usize) -> String {
        let spacing = " ".repeat(indent);
        let path_str = print_path(self.path.clone());
        let inner = self.value.debug_view(indent + 2);
        format!("LWW Register CRDT @ /{path_str}\n{spacing}{inner}")
    }
}

impl<T> Debug for LWWRegisterCRDT<T>
where
    T: CRDTNode,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.value.id)
    }
}

#[cfg(test)]
mod test {
    use super::LWWRegisterCRDT;
    use crate::keypair::make_author;

    #[test]
    fn test_lww_simple() {
        let mut register = LWWRegisterCRDT::new(make_author(1), vec![]);
        assert_eq!(register.view(), None);
        register.set(1);
        assert_eq!(register.view(), Some(1));
        register.set(99);
        assert_eq!(register.view(), Some(99));
    }

    #[test]
    fn test_lww_multiple_writer() {
        let mut register1 = LWWRegisterCRDT::new(make_author(1), vec![]);
        let mut register2 = LWWRegisterCRDT::new(make_author(2), vec![]);
        let _a = register1.set('a');
        let _b = register1.set('b');
        let _c = register2.set('c');
        assert_eq!(register2.view(), Some('c'));
        register1.apply(_c);
        register2.apply(_b);
        register2.apply(_a);
        assert_eq!(register1.view(), Some('b'));
        assert_eq!(register2.view(), Some('b'));
    }

    #[test]
    fn test_lww_idempotence() {
        let mut register = LWWRegisterCRDT::new(make_author(1), vec![]);
        let op = register.set(1);
        for _ in 1..10 {
            register.apply(op.clone());
        }
        assert_eq!(register.view(), Some(1));
    }

    #[test]
    fn test_lww_consistent_tiebreak() {
        let mut register1 = LWWRegisterCRDT::new(make_author(1), vec![]);
        let mut register2 = LWWRegisterCRDT::new(make_author(2), vec![]);
        let _a = register1.set('a');
        let _b = register2.set('b');
        register1.apply(_b);
        register2.apply(_a);
        let _c = register1.set('c');
        let _d = register2.set('d');
        register2.apply(_c);
        register1.apply(_d);
        assert_eq!(register1.view(), register2.view());
        assert_eq!(register1.view(), Some('c'));
    }
}
