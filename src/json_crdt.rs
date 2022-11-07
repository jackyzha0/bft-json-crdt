use crate::{
    keypair::{make_keypair, AuthorID},
    list_crdt::ListCRDT,
    lww_crdt::LWWRegisterCRDT,
    map_crdt::MapCRDT,
    op::{Op, OpID, PathSegment},
};
pub use bft_crdt_derive::*;
use fastcrypto::{ed25519::Ed25519KeyPair, traits::KeyPair};
use std::{any::Any, collections::HashMap, fmt::Display, marker::PhantomData};

#[derive(Clone)]
pub enum Terminal {
    Bool(bool),
    Number(f32),
    String(String),
    Char(char),
}

pub trait InnerCRDT: Any + Clone {}

#[derive(Clone)]
pub enum OpVal<T> {
    Nested(T),
    Terminal(Terminal),
}

pub trait CRDT<'t> {
    type From: IntoCRDT<To<'t> = Self> + Clone + 't;
    fn apply(&mut self, op: Op<Self::From>);
    fn view(&self) -> Option<&Self::From>;
}

pub trait IntoCRDT {
    type To<'t>: CRDT<'t, From = Self>
    where
        Self: 't;
    fn to_crdt(self, keypair: &Ed25519KeyPair, path: Vec<PathSegment>) -> Self::To<'_>;
}

impl IntoCRDT for f32 {
    type To<'a> = LWWRegisterCRDT<'a, Self> where Self: 'a;
    fn to_crdt(self, keypair: &Ed25519KeyPair, path: Vec<PathSegment>) -> Self::To<'_> {
        LWWRegisterCRDT::new(keypair, path)
    }
}

// impl Display for Terminal {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(
//             f,
//             "{}",
//             match self {
//                 Terminal::Bool(val) => val.to_string(),
//                 Terminal::String(str) => format!("\"{str}\""),
//                 Terminal::Number(n) => n.to_string(),
//             }
//         )
//     }
// }
//
// impl<'a, T> Display for JsonStructValue<'a, T> {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(
//             f,
//             "{}",
//             match self {
//                 JsonStructValue::Terminal(term) => term.to_string(),
//                 JsonStructValue::Object(object) => object.to_string(),
//                 JsonStructValue::Array(arr) => arr.to_string(),
//                 JsonStructValue::Nested(map) => map
//                     .iter()
//                     .map(|(k, v)| format!("{k}: {v}"))
//                     .collect::<Vec<_>>()
//                     .join(", "),
//             }
//         )
//     }
// }
//

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
}

#[cfg(test)]
mod test {
    use crate::json_crdt::{BaseCRDT, IntoCRDT, CRDT};
    use crate::keypair::make_keypair;
    use crate::op::Op;
    use crate::op::PathSegment;
    use fastcrypto::ed25519::Ed25519KeyPair;
    use fastcrypto::traits::KeyPair;

    #[test]
    fn test_derive_basic() {
        // #[derive(Clone, IntoCRDT)]
        // struct Player {
        //     x: f32,
        //     y: f32,
        // }
        //
        // let p = Player { x: 0.0, y: 0.0 };
        // let keypair = make_keypair();
        // let crdt = BaseCRDT::new(p, &keypair);
        // crdt.doc.x;
    }
}
