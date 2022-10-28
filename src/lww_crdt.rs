use crate::op::{Op, SequenceNumber};
use fastcrypto::{ed25519::Ed25519KeyPair, traits::KeyPair};
use std::cmp::{max, Ordering};
use std::{collections::HashMap, fmt::Display};

use crate::keypair::AuthorID;

pub struct LWWRegisterCRDT<'a, T>
where
    T: Clone + Display,
{
    pub our_id: AuthorID,
    keypair: &'a Ed25519KeyPair,
    value: Op<T>,
    logical_clocks: HashMap<AuthorID, SequenceNumber>,
    highest_seq: SequenceNumber,
}

impl<T> LWWRegisterCRDT<'_, T>
where
    T: Clone + Display,
{
    pub fn new(keypair: &Ed25519KeyPair) -> LWWRegisterCRDT<'_, T> {
        let id = keypair.public().0.to_bytes();
        let mut logical_clocks = HashMap::new();
        logical_clocks.insert(id, 0);
        LWWRegisterCRDT {
            our_id: id,
            keypair,
            value: Op::make_root(),
            logical_clocks,
            highest_seq: 0,
        }
    }

    pub fn our_seq(&self) -> SequenceNumber {
        *self.logical_clocks.get(&self.our_id).unwrap()
    }

    pub fn set(&mut self, val: T) -> Op<T> {
        let op = Op::new(
            self.value.id,
            self.our_id,
            self.our_seq() + 1,
            false,
            Some(val),
            self.keypair,
        );
        self.apply(op.clone());
        op
    }

    pub fn apply(&mut self, op: Op<T>) {
        #[cfg(feature = "bft")]
        if !op.is_valid() {
            return;
        }

        let author = op.author();
        let seq = op.sequence_num();

        // take most recent update by sequence number
        match seq.cmp(&self.our_seq()) {
            Ordering::Greater => self.value = op,
            Ordering::Equal => {
                // if we are equal, tie break on author
                if op.author() < self.our_id {
                    self.value = op
                }
            }
            Ordering::Less => {} // LWW, ignore if its outdate
        };

        // update bookkeeping
        self.logical_clocks.insert(author, seq);
        self.highest_seq = max(self.highest_seq, seq);
        self.logical_clocks.insert(self.our_id, self.highest_seq);
    }

    pub fn view(&self) -> Option<&T> {
        self.value.content.as_ref()
    }
}

#[cfg(test)]
mod test {
    use super::LWWRegisterCRDT;
    use crate::keypair::make_keypair;

    #[test]
    fn test_lww_simple() {
        let key = make_keypair();
        let mut register = LWWRegisterCRDT::new(&key);
        assert_eq!(register.view(), None);
        register.set(1);
        assert_eq!(register.view(), Some(&1));
        register.set(99);
        assert_eq!(register.view(), Some(&99));
    }

    #[test]
    fn test_lww_multiple_writer() {
        let key1 = make_keypair();
        let key2 = make_keypair();
        let mut register1 = LWWRegisterCRDT::new(&key1);
        let mut register2 = LWWRegisterCRDT::new(&key2);
        let _a = register1.set('a');
        let _b = register1.set('b');
        let _c = register2.set('c');
        assert_eq!(register2.view(), Some(&'c'));
        register1.apply(_c);
        register2.apply(_b);
        register2.apply(_a);
        assert_eq!(register1.view(), Some(&'b'));
        assert_eq!(register2.view(), Some(&'b'));
    }

    #[test]
    fn test_lww_idempotence() {
        let key = make_keypair();
        let mut register = LWWRegisterCRDT::new(&key);
        let op = register.set(1);
        for _ in 1..10 {
            register.apply(op);
        }
        assert_eq!(register.view(), Some(&1));
    }

    #[test]
    fn test_lww_consistent_tiebreak() {
        let key1 = make_keypair();
        let key2 = make_keypair();
        let mut register1 = LWWRegisterCRDT::new(&key1);
        let mut register2 = LWWRegisterCRDT::new(&key2);
        let _a = register1.set('a');
        let _b = register2.set('b');
        register1.apply(_b);
        register2.apply(_a);
        let _c = register1.set('c');
        let _d = register2.set('d');
        register2.apply(_c);
        register1.apply(_d);
        assert_eq!(register1.view(), register2.view());
    }
}
