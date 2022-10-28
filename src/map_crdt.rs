use fastcrypto::{ed25519::Ed25519KeyPair, traits::KeyPair};
use std::{
    cmp::{max, Ordering},
    fmt::{Formatter, Result},
};

use crate::op::{Op, OpID, SequenceNumber, ROOT_ID};
use std::{collections::HashMap, fmt::Display};

use crate::keypair::AuthorID;

pub struct MapCRDT<'a, T>
where
    T: Clone + Display,
{
    pub our_id: AuthorID,
    keypair: &'a Ed25519KeyPair,
    table: HashMap<String, Op<Register<T>>>,
    logical_clocks: HashMap<AuthorID, SequenceNumber>,
    highest_seq: SequenceNumber,
    message_q: HashMap<OpID, Vec<Op<Register<T>>>>,
}

#[derive(Clone)]
pub struct Register<T: Display + Clone> {
    key: String,
    value: T,
}

impl<T> Display for Register<T>
where
    T: Clone + Display,
{
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "\"{}\": {}", self.key, self.value)
    }
}

impl<T> MapCRDT<'_, T>
where
    T: Clone + Display,
{
    pub fn new(keypair: &Ed25519KeyPair) -> MapCRDT<'_, T> {
        let id = keypair.public().0.to_bytes();
        let mut logical_clocks = HashMap::new();
        logical_clocks.insert(id, 0);
        MapCRDT {
            our_id: id,
            keypair,
            table: HashMap::new(),
            logical_clocks,
            highest_seq: 0,
            message_q: HashMap::new(),
        }
    }

    pub fn our_seq(&self) -> SequenceNumber {
        *self.logical_clocks.get(&self.our_id).unwrap()
    }

    fn find(&self, id: OpID) -> Option<&String> {
        self.table
            .values()
            .find(|op| op.id == id && op.content.is_some())
            .map(|op| {
                let Register { key, value: _ } = op.content.as_ref().unwrap();
                key
            })
    }

    pub fn set(&mut self, key: String, value: T) -> Op<Register<T>> {
        let op = Op::new(
            ROOT_ID,
            self.our_id,
            self.our_seq() + 1,
            false,
            Some(Register { key, value }),
            self.keypair,
        );
        self.apply(op.clone());
        op
    }

    pub fn delete(&mut self, op_id: OpID) -> Op<Register<T>> {
        let op = Op::new(
            op_id,
            self.our_id,
            self.our_seq() + 1,
            true,
            None,
            self.keypair,
        );
        self.apply(op.clone());
        op
    }

    pub fn apply(&mut self, op: Op<Register<T>>) {
        #[cfg(feature = "bft")]
        if !op.is_valid() {
            return;
        }

        let op_id = op.id;
        let author = op.author();
        let seq = op.sequence_num();

        // wait on a causal dependency if there is one (for deletes)
        if op.origin != ROOT_ID && self.find(op.origin).is_none() {
            self.message_q.entry(op.origin).or_default().push(op);
            return;
        }

        self.integrate(op);

        // update bookkeeping
        self.logical_clocks.insert(author, seq);
        self.highest_seq = max(self.highest_seq, seq);
        self.logical_clocks.insert(self.our_id, self.highest_seq);

        // apply all of its causal dependents if there are any
        let dependent_queue = self.message_q.remove(&op_id);
        if let Some(mut q) = dependent_queue {
            for dependent in q.drain(..) {
                self.apply(dependent);
            }
        }
    }

    fn integrate(&mut self, new_op: Op<Register<T>>) {
        if new_op.is_deleted {
            let maybe_old = self.find(new_op.origin);
            if let Some(key) = maybe_old {
                self.table.get_mut(&key.to_owned()).unwrap().is_deleted = true;
            }
            return;
        }

        // content is guaranteed to be non-None as per op.is_valid()
        let seq = new_op.sequence_num();
        let Register { key, value: _ } = new_op.content.as_ref().unwrap();
        let old_seq = self.table.get(key).map(|op| op.sequence_num()).unwrap_or(0);

        // insert new one
        match seq.cmp(&old_seq) {
            Ordering::Greater => {
                self.table.insert(key.to_owned(), new_op);
            }
            Ordering::Equal => {
                // if we are equal, tie break on author
                if new_op.author() < self.our_id {
                    self.table.insert(key.to_owned(), new_op);
                }
            }
            Ordering::Less => {} // LWW, ignore if its outdate
        };
    }

    pub fn view(&self) -> HashMap<String, &T> {
        let mut res = HashMap::new();
        self.table.iter().for_each(|(_, op)| {
            if op.content.is_some() && !op.is_deleted {
                let register = op.content.as_ref().unwrap();
                res.insert(register.key.clone(), &register.value);
            }
        });
        res
    }
}

#[cfg(test)]
mod test {
    use itertools::sorted;

    use super::MapCRDT;
    use crate::keypair::make_keypair;

    #[test]
    fn test_map_simple() {
        let key = make_keypair();
        let mut map = MapCRDT::new(&key);
        assert_eq!(map.view().keys().len(), 0);
        map.set("asdf".to_string(), 3);
        assert_eq!(map.view().keys().len(), 1);
        assert_eq!(map.view().get("asdf").unwrap(), &&3);
        map.set("test".to_string(), 1);
        map.set("asdf".to_string(), 5);
        assert_eq!(map.view().keys().len(), 2);
        assert_eq!(map.view().get("asdf").unwrap(), &&5);
        assert_eq!(map.view().get("test").unwrap(), &&1);
    }

    #[test]
    fn test_map_delete() {
        let key = make_keypair();
        let mut map = MapCRDT::new(&key);
        let _a = map.set("a".to_string(), 'a');
        assert_eq!(map.view().keys().len(), 1);
        map.delete(_a.id);
        assert_eq!(map.view().keys().len(), 0);
        map.apply(_a);
        assert_eq!(map.view().keys().len(), 0);
        let _b = map.set("a".to_string(), 'b');
        assert_eq!(map.view().get("a").unwrap(), &&'b');
    }

    #[test]
    fn test_map_idempotence() {
        let key = make_keypair();
        let mut map = MapCRDT::new(&key);
        let op = map.set("a".to_string(), 1);
        let _op2 = map.set("a".to_string(), 2);
        for _ in 1..10 {
            map.apply(op.clone());
        }
        assert_eq!(map.view().get("a").unwrap(), &&2);
        assert_eq!(map.view().keys().len(), 1);
    }

    #[test]
    fn test_map_interleaving_access() {
        let key1 = make_keypair();
        let key2 = make_keypair();
        let mut map1 = MapCRDT::new(&key1);
        let mut map2 = MapCRDT::new(&key2);

        let _a = map1.set("a".to_string(), 'a');
        let _b = map2.set("b".to_string(), 'b');
        let _c = map2.set("c".to_string(), 'c');
        let _d = map2.set("a".to_string(), 'd');
        let _e = map1.set("a".to_string(), 'e');
        let _f = map1.set("f".to_string(), 'f');
        map2.apply(_a);
        map2.apply(_e);
        map2.apply(_f);
        map1.apply(_b);
        map1.apply(_d);
        map1.apply(_c);

        let m1view = map1.view();
        let m2view = map2.view();
        let map1keys = sorted(m1view.keys());
        let map2keys = sorted(m2view.keys());
        let map1vals = sorted(m1view.values());
        let map2vals = sorted(m2view.values());
        assert_eq!(map1keys.len(), 4);
        assert_eq!(map1keys.len(), map2keys.len());
        assert_eq!(map1vals.len(), map2vals.len());
        assert!(map1keys.eq(map2keys));
        assert!(map1vals.eq(map2vals));
    }
}
