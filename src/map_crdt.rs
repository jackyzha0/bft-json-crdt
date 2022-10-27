use fastcrypto::{ed25519::Ed25519KeyPair, traits::KeyPair};
use std::{
    cmp::max,
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
    table: HashMap<OpID, Op<Register<T>>>,
    index: HashMap<String, OpID>,
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
            index: HashMap::new(),
            logical_clocks,
            highest_seq: 0,
            message_q: HashMap::new(),
        }
    }

    pub fn our_seq(&self) -> SequenceNumber {
        *self.logical_clocks.get(&self.our_id).unwrap()
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

    pub fn delete(&mut self, key: String) -> Op<Register<T>> {
        let op_id = *self.index.get(&key).unwrap();
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

        let author = op.author();
        let seq = op.sequence_num();

        // insert case
        if op.origin == ROOT_ID {
            let Register { key, value: _ } = op.content.clone().unwrap();
            self.index.insert(key, op.id);
            self.table.insert(op.id, op);
            return;
        }

        // update bookkeeping
        self.logical_clocks.insert(author, seq);
        self.highest_seq = max(self.highest_seq, seq);
        self.logical_clocks.insert(self.our_id, self.highest_seq);
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
    // use super::MapCRDT;
    // use crate::keypair::make_keypair;
}
