use std::collections::HashMap;

use crate::{
    keypair::AuthorID,
    op::{Hashable, Op, PathSegment},
};
pub use bft_crdt_derive::*;
use fastcrypto::{ed25519::Ed25519KeyPair, traits::KeyPair};

pub trait CRDT<'t> {
    type Inner: Hashable + Clone + 't;
    type View;
    fn apply(&mut self, op: Op<Self::Inner>);
    fn view(&'t self) -> Self::View;
    fn new(keypair: &'t Ed25519KeyPair, path: Vec<PathSegment>) -> Self;
}

#[allow(dead_code)]
pub struct BaseCRDT<'a, T: CRDT<'a>> {
    id: AuthorID,
    keypair: &'a Ed25519KeyPair,
    doc: T,
}

impl<'a, T: CRDT<'a>> BaseCRDT<'a, T> {
    #[allow(dead_code)]
    fn new(keypair: &'a Ed25519KeyPair) -> Self {
        let id = keypair.public().0.to_bytes();
        Self {
            id,
            keypair,
            doc: T::new(keypair, vec![]),
        }
    }

    fn view(&'a self) -> T::View {
        self.doc.view()
    }
}

#[derive(Clone, Debug)]
pub enum Value {
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(HashMap<String, Value>),
}

impl TryFrom<Value> for bool {
    type Error = ();
    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Bool(x) = value {
            Ok(x)
        } else {
            Err(())
        }
    }
}

impl From<bool> for Value {
    fn from(val: bool) -> Self {
        Value::Bool(val)
    }
}

impl TryFrom<Value> for f64 {
    type Error = ();
    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Number(x) = value {
            Ok(x)
        } else {
            Err(())
        }
    }
}

impl From<f64> for Value {
    fn from(val: f64) -> Self {
        Value::Number(val)
    }
}

impl TryFrom<Value> for String {
    type Error = ();
    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::String(x) = value {
            Ok(x)
        } else {
            Err(())
        }
    }
}

impl From<String> for Value {
    fn from(val: String) -> Self {
        Value::String(val)
    }
}

#[cfg(test)]
mod test {
    use bft_crdt_derive::add_path_field;

    use crate::{
        json_crdt::{BaseCRDT, CRDT},
        keypair::make_keypair,
        list_crdt::ListCRDT,
        lww_crdt::LWWRegisterCRDT,
        op::print_path,
    };

    #[test]
    fn test_derive_basic() {
        #[add_path_field]
        #[derive(Debug, Clone, CRDT)]
        struct Player<'t> {
            x: LWWRegisterCRDT<'t, f64>,
            y: LWWRegisterCRDT<'t, f64>,
        }

        let keypair = make_keypair();
        let crdt = BaseCRDT::<Player>::new(&keypair);
        assert_eq!(print_path(crdt.doc.x.path), "x");
        assert_eq!(print_path(crdt.doc.y.path), "y");
    }

    #[test]
    fn test_derive_nested() {
        #[add_path_field]
        #[derive(Debug, Clone, CRDT)]
        struct Position<'t> {
            x: LWWRegisterCRDT<'t, f64>,
            y: LWWRegisterCRDT<'t, f64>,
        }

        #[add_path_field]
        #[derive(Debug, Clone, CRDT)]
        struct Player<'t> {
            pos: Position<'t>,
            balance: LWWRegisterCRDT<'t, f64>,
            messages: ListCRDT<'t, String>,
        }

        let keypair = make_keypair();
        let crdt = BaseCRDT::<Player>::new(&keypair);
        assert_eq!(print_path(crdt.doc.pos.x.path), "pos.x");
        assert_eq!(print_path(crdt.doc.pos.y.path), "pos.y");
        assert_eq!(print_path(crdt.doc.balance.path), "balance");
        assert_eq!(print_path(crdt.doc.messages.path), "messages");
    }

    #[test]
    fn test_lww_ops() {
        #[add_path_field]
        #[derive(Debug, Clone, CRDT)]
        struct Test<'t> {
            a: LWWRegisterCRDT<'t, f64>,
            b: LWWRegisterCRDT<'t, bool>,
            c: LWWRegisterCRDT<'t, String>,
        }

        let kp1 = make_keypair();
        let kp2 = make_keypair();
        let mut base1 = BaseCRDT::<Test>::new(&kp1);
        let mut base2 = BaseCRDT::<Test>::new(&kp2);

        let _1_a_1 = base1.doc.a.set(3.0);
        let _1_b_1 = base1.doc.b.set(true);
        let _2_a_1 = base2.doc.a.set(1.5);
        let _2_a_2 = base2.doc.a.set(2.13);
        let _2_c_1 = base2.doc.c.set("abc".to_string());

        assert_eq!(base1.doc.a.view(), Some(3.0));
        assert_eq!(base2.doc.a.view(), Some(2.13));
        assert_eq!(base1.doc.b.view(), Some(true));
        assert_eq!(base2.doc.c.view(), Some("abc".to_string()));

        base2.doc.apply(_1_a_1.into());
        base2.doc.apply(_1_b_1.into());
        base1.doc.apply(_2_a_1.into());
        base1.doc.apply(_2_a_2.into());
        base1.doc.apply(_2_c_1.into());
    }

    #[test]
    fn test_vec_ops() {}

    #[test]
    fn test_map_ops() {}

    #[test]
    fn test_nested_ops() {}
}
