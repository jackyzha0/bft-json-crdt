use fastcrypto::ed25519::Ed25519KeyPair;
use std::{collections::HashMap, fmt::Display};

use crate::{
    keypair::AuthorID,
    list_crdt::ListCRDT,
    lww_crdt::LWWRegisterCRDT,
    map_crdt::MapCRDT,
    op::{Op, OpID, PathSegment},
};

#[derive(Clone)]
pub enum Terminal {
    Null,
    Bool(bool),
    Number(f32),
    String(String),
}

impl Display for Terminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Terminal::Null => "null".to_string(),
                Terminal::Bool(val) => val.to_string(),
                Terminal::String(str) => format!("\"{str}\""),
                Terminal::Number(n) => n.to_string(),
            }
        )
    }
}

impl<'a> Display for JsonStructValue<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                JsonStructValue::Terminal(term) => term.to_string(),
                JsonStructValue::Object(object) => object.to_string(),
                JsonStructValue::Array(arr) => arr.to_string(),
                JsonStructValue::Nested(map) => map.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>().join(", "),
            }
        )
    }
}

#[derive(Clone)]
pub enum JsonStructValue<'a> {
    Terminal(LWWRegisterCRDT<'a, Terminal>),
    Object(MapCRDT<'a, JsonStructValue<'a>>),
    Array(ListCRDT<'a, JsonStructValue<'a>>),
    Nested(DocType<'a>),
}

pub struct WrappedOp {
    op: Op<Terminal>,
    path: Vec<OpID>,
}

pub type DocType<'a> = HashMap<String, JsonStructValue<'a>>;
pub struct ConcreteCRDT<'a, T> {
    id: AuthorID,
    keypair: Ed25519KeyPair,
    doc: DocType<'a>,
    pub path: Vec<PathSegment>,
    view: T,
}

pub trait CRDT<T> {
    fn apply(&mut self, op: WrappedOp);
    fn view(&self) -> T;
}

// A JSON object that is static
pub trait IntoCRDT<'a, T> {
    fn into_crdt(self) -> ConcreteCRDT<'a, T>;
}

#[cfg(test)]
mod test {
    use bft_crdt_derive::IntoCRDT;

    #[test]
    fn test_derive_basic() {
        #[derive(IntoCRDT)]
        struct Player {
            x: f32,
            y: f32,
        }
    }
}
