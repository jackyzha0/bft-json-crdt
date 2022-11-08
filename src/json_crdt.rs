use crate::{
    keypair::{make_keypair, AuthorID},
    list_crdt::ListCRDT,
    lww_crdt::LWWRegisterCRDT,
    map_crdt::MapCRDT,
    op::{Op, OpID, Hashable, PathSegment},
};
pub use bft_crdt_derive::*;
use fastcrypto::{ed25519::Ed25519KeyPair, traits::KeyPair};
use std::{any::Any, collections::HashMap, fmt::{Display, Debug}};

#[derive(Clone)]
pub enum Terminal {
    Bool(bool),
    Number(f32),
    String(String),
    Char(char),
}

#[derive(Clone)]
pub enum OpVal<T> {
    Nested(T),
    Terminal(Terminal),
}

pub trait CRDT<'t> {
    type Inner: Hashable + Clone + 't;
    type View;
    fn apply(&mut self, op: Op<Self::Inner>);
    fn view(&'t self) -> Self::View;
    fn new(keypair: &'t Ed25519KeyPair, path: Vec<PathSegment>) -> Self;
}

pub struct BaseCRDT<'a, T: CRDT<'a>> {
    id: AuthorID,
    keypair: &'a Ed25519KeyPair,
    doc: T,
    pub path: Vec<PathSegment>,
}

impl<'a, T: CRDT<'a>> BaseCRDT<'a, T> {
    fn set_path(&mut self, path: Vec<PathSegment>) {
        self.path = path;
    }

    fn new(keypair: &'a Ed25519KeyPair) -> Self {
        let id = keypair.public().0.to_bytes();
        Self {
            id,
            keypair,
            doc: T::new(keypair, vec![]),
            path: vec![],
        }
    }
}

#[cfg(test)]
mod test {
    use bft_crdt_derive::add_path_field;

    use crate::{
        json_crdt::{BaseCRDT, CRDT},
        keypair::make_keypair,
        lww_crdt::LWWRegisterCRDT, op::print_path,
    };

    #[test]
    fn test_derive_basic() {
        #[derive(Debug, Clone, CRDT)]
        struct Player<'t> {
            x: LWWRegisterCRDT<'t, f32>,
            y: LWWRegisterCRDT<'t, f32>,
        }

        let keypair = make_keypair();
        let crdt = BaseCRDT::<Player>::new(&keypair);
        assert_eq!(print_path(crdt.doc.x.path), "x");
        assert_eq!(print_path(crdt.doc.y.path), "y");
    }
}
