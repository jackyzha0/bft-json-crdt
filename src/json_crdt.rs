use std::collections::{HashMap, HashSet};

use crate::{
    keypair::AuthorID,
    list_crdt::ListCRDT,
    lww_crdt::LWWRegisterCRDT,
    op::{Hashable, Op, OpID, PathSegment, ROOT_ID},
};
pub use bft_crdt_derive::*;
use fastcrypto::{ed25519::Ed25519KeyPair, traits::KeyPair};

pub trait CRDT<'t> {
    type Inner: Hashable + Clone + 't;
    type View;
    fn apply(&mut self, op: Op<Self::Inner>);
    fn view(&self) -> Self::View;
    fn new(keypair: &'t Ed25519KeyPair, path: Vec<PathSegment>) -> Self;
}

#[allow(dead_code)]
pub struct BaseCRDT<'a, T: CRDT<'a>> {
    id: AuthorID,
    keypair: &'a Ed25519KeyPair,
    doc: T,

    /// In a real world scenario, this would be a hashgraph
    delivered: HashSet<OpID>,
    message_q: HashMap<OpID, Vec<Op<T::Inner>>>,
}

pub struct JSONOp {
    inner: Op<Value>,
    origin: Option<OpID>,
}

impl JSONOp {
    fn depends_on(self, origin: OpID) -> Self {
        Self {
            origin: Some(origin),
            ..self
        }
    }
}

impl<T> From<Op<T>> for JSONOp
where
    T: Hashable + Clone + Into<Value>,
{
    fn from(value: Op<T>) -> Self {
        Self {
            inner: Op {
                content: value.content.map(|c| c.into()),
                origin: value.origin,
                author: value.author,
                seq: value.seq,
                path: value.path,
                is_deleted: value.is_deleted,
                id: value.id,
                signed_digest: value.signed_digest,
            },
            origin: None,
        }
    }
}

#[allow(dead_code)]
impl<'a, T: CRDT<'a, Inner = Value>> BaseCRDT<'a, T> {
    fn new(keypair: &'a Ed25519KeyPair) -> Self {
        let id = keypair.public().0.to_bytes();
        Self {
            id,
            keypair,
            doc: T::new(keypair, vec![]),
            delivered: HashSet::new(),
            message_q: HashMap::new(),
        }
    }

    fn apply(&mut self, op: JSONOp) {
        if op.origin.is_none() {
            self.doc.apply(op.inner);
            return;
        }

        let op_id = op.inner.id;
        let origin = op.origin.unwrap();
        // we haven't seen causal dependency, queue it for later
        if !self.delivered.contains(&origin) {
            self.message_q.entry(origin).or_default().push(op.inner);
            return;
        }

        // otherwise, we are good to deliver
        self.doc.apply(op.inner);

        // apply all of its causal dependents if there are any
        let dependent_queue = self.message_q.remove(&op_id);
        if let Some(mut q) = dependent_queue {
            for dependent in q.drain(..) {
                self.apply(JSONOp {
                    inner: dependent,
                    origin: None,
                });
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(HashMap<String, Value>),
}

impl Default for Value {
    fn default() -> Self {
        Self::Null
    }
}

impl From<Value> for serde_json::Value {
    fn from(value: Value) -> Self {
        match value {
            Value::Null => serde_json::Value::Null,
            Value::Bool(x) => serde_json::Value::Bool(x),
            Value::Number(x) => serde_json::Value::Number(serde_json::Number::from_f64(x).unwrap()),
            Value::String(x) => serde_json::Value::String(x),
            Value::Array(x) => {
                serde_json::Value::Array(x.iter().map(|a| a.clone().into()).collect())
            }
            Value::Object(x) => serde_json::Value::Object(
                x.iter()
                    .map(|(k, v)| (k.clone(), v.clone().into()))
                    .collect(),
            ),
        }
    }
}

impl From<serde_json::Value> for Value {
    fn from(value: serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => Value::Null,
            serde_json::Value::Bool(x) => Value::Bool(x),
            serde_json::Value::Number(x) => Value::Number(x.as_f64().unwrap()),
            serde_json::Value::String(x) => Value::String(x),
            serde_json::Value::Array(x) => {
                Value::Array(x.iter().map(|a| a.clone().into()).collect())
            }
            serde_json::Value::Object(x) => Value::Object(
                x.iter()
                    .map(|(k, v)| (k.clone(), v.clone().into()))
                    .collect(),
            ),
        }
    }
}

impl Value {
    #[allow(dead_code)]
    fn into_json(self) -> serde_json::Value {
        self.into()
    }
}

// primitives -> Value
impl From<bool> for Value {
    fn from(val: bool) -> Self {
        Value::Bool(val)
    }
}

impl From<f64> for Value {
    fn from(val: f64) -> Self {
        Value::Number(val)
    }
}

impl From<String> for Value {
    fn from(val: String) -> Self {
        Value::String(val)
    }
}

impl<T> From<Option<T>> for Value
where
    T: Into<Value> + Hashable + Clone,
{
    fn from(val: Option<T>) -> Self {
        match val {
            Some(x) => x.into(),
            None => Value::Null,
        }
    }
}

impl<'a, T> From<T> for Value
where
    T: CRDT<'a, Inner = Value, View = Value>,
{
    fn from(value: T) -> Self {
        value.view()
    }
}

impl<'a, T> From<ListCRDT<'a, T>> for Value
where
    T: Hashable + Clone + Into<Value>,
{
    fn from(value: ListCRDT<'a, T>) -> Self {
        value.view().into()
    }
}

impl<'a, T> From<LWWRegisterCRDT<'a, T>> for Value
where
    T: Hashable + Clone + Into<Value>,
{
    fn from(value: LWWRegisterCRDT<'a, T>) -> Self {
        value.view().into()
    }
}

impl<T> From<Vec<T>> for Value
where
    T: Into<Value> + Hashable + Clone,
{
    fn from(value: Vec<T>) -> Self {
        Value::Array(value.iter().map(|x| x.clone().into()).collect())
    }
}

impl<T> From<HashMap<String, T>> for Value
where
    T: Into<Value> + Hashable + Clone,
{
    fn from(value: HashMap<String, T>) -> Self {
        Value::Object(
            value
                .iter()
                .map(|(k, v)| (k.clone(), v.clone().into()))
                .collect(),
        )
    }
}

/// Both traits below are reflexive as From/Into are reflexive so these are too
/// Equivalent to [`TryFrom`] except with [`Option`] instead of [`Result`].
/// It takes in a keypair to allow creating new CRDTs from a bare [`Value`]
pub trait CRDTTerminalFrom<'a, T>: Sized {
    fn terminal_from(value: T, keypair: &'a Ed25519KeyPair, path: Vec<PathSegment>)
        -> Option<Self>;
}

/// Equivalent to [`TryInto`] except with [`Option`] instead of [`Result`].
/// It takes in a keypair to allow creating new CRDTs from a bare [`Value`]
pub trait IntoCRDTTerminal<'a, T>: Sized {
    fn into_terminal(self, keypair: &'a Ed25519KeyPair, path: Vec<PathSegment>) -> Option<T>;
}

/// Equivalent to infallible conversions
/// Automatically implement [`CRDTTerminalFrom`] for anything that implements [`Into`]
impl<T, U> CRDTTerminalFrom<'_, U> for T
where
    U: Into<T>,
{
    fn terminal_from(value: U, _keypair: &Ed25519KeyPair, _path: Vec<PathSegment>) -> Option<Self> {
        Some(U::into(value))
    }
}

/// CRDTTerminalFrom implies CRDTTerminalFrom
impl<'a, T, U> IntoCRDTTerminal<'a, U> for T
where
    U: CRDTTerminalFrom<'a, T>,
{
    fn into_terminal(self, keypair: &'a Ed25519KeyPair, path: Vec<PathSegment>) -> Option<U> {
        U::terminal_from(self, keypair, path)
    }
}

impl CRDTTerminalFrom<'_, Value> for bool {
    fn terminal_from(
        value: Value,
        _keypair: &Ed25519KeyPair,
        _path: Vec<PathSegment>,
    ) -> Option<Self> {
        if let Value::Bool(x) = value {
            Some(x)
        } else {
            None
        }
    }
}

impl CRDTTerminalFrom<'_, Value> for f64 {
    fn terminal_from(
        value: Value,
        _keypair: &Ed25519KeyPair,
        _path: Vec<PathSegment>,
    ) -> Option<Self> {
        if let Value::Number(x) = value {
            Some(x)
        } else {
            None
        }
    }
}

impl CRDTTerminalFrom<'_, Value> for String {
    fn terminal_from(
        value: Value,
        _keypair: &Ed25519KeyPair,
        _path: Vec<PathSegment>,
    ) -> Option<Self> {
        if let Value::String(x) = value {
            Some(x)
        } else {
            None
        }
    }
}

impl<'a, T> CRDTTerminalFrom<'a, Value> for LWWRegisterCRDT<'a, T>
where
    T: CRDTTerminalFrom<'a, Value> + Clone + Hashable,
{
    fn terminal_from(
        value: Value,
        keypair: &'a Ed25519KeyPair,
        path: Vec<PathSegment>,
    ) -> Option<Self> {
        if let Some(term) = value.into_terminal(keypair, path.clone()) {
            let mut crdt = LWWRegisterCRDT::new(keypair, path);
            crdt.set(term);
            Some(crdt)
        } else {
            None
        }
    }
}

impl<'a, T> CRDTTerminalFrom<'a, Value> for ListCRDT<'a, T>
where
    T: CRDTTerminalFrom<'a, Value> + Clone + Hashable,
{
    fn terminal_from(
        value: Value,
        keypair: &'a Ed25519KeyPair,
        path: Vec<PathSegment>,
    ) -> Option<Self> {
        if let Some(term) = value.into_terminal(keypair, path.clone()) {
            let mut crdt = ListCRDT::new(keypair, path);
            crdt.insert::<Value>(ROOT_ID, term);
            Some(crdt)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use bft_crdt_derive::add_crdt_fields;
    use serde_json::json;

    use crate::{
        json_crdt::{BaseCRDT, IntoCRDTTerminal, Value, CRDT},
        keypair::make_keypair,
        list_crdt::ListCRDT,
        lww_crdt::LWWRegisterCRDT,
        op::{print_path, ROOT_ID},
    };

    #[test]
    fn test_derive_basic() {
        #[add_crdt_fields]
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
        #[add_crdt_fields]
        #[derive(Debug, Clone, CRDT)]
        struct Position<'t> {
            x: LWWRegisterCRDT<'t, f64>,
            y: LWWRegisterCRDT<'t, f64>,
        }

        #[add_crdt_fields]
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
        #[add_crdt_fields]
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

        assert_eq!(
            base1.doc.view().into_json(),
            json!({
                "a": 3.0,
                "b": true,
                "c": null,
            })
        );
        assert_eq!(
            base2.doc.view().into_json(),
            json!({
                "a": 2.13,
                "b": null,
                "c": "abc",
            })
        );

        base2.apply(_1_a_1.export());
        base2.apply(_1_b_1.export());
        base1.apply(_2_a_1.export());
        base1.apply(_2_a_2.export());
        base1.apply(_2_c_1.export());

        assert_eq!(base1.doc.view().into_json(), base2.doc.view().into_json());
        assert_eq!(
            base1.doc.view().into_json(),
            json!({
                "a": 2.13,
                "b": true,
                "c": "abc"
            })
        )
    }

    #[test]
    fn test_vec_and_map_ops() {
        #[add_crdt_fields]
        #[derive(Debug, Clone, CRDT)]
        struct Test<'t> {
            a: ListCRDT<'t, String>,
        }

        let kp1 = make_keypair();
        let kp2 = make_keypair();
        let mut base1 = BaseCRDT::<Test>::new(&kp1);
        let mut base2 = BaseCRDT::<Test>::new(&kp2);

        let _1a = base1.doc.a.insert(ROOT_ID, "a".to_string());
        let _1b = base1.doc.a.insert(_1a.id, "b".to_string());
        let _2c = base2.doc.a.insert(ROOT_ID, "c".to_string());
        let _2d = base2.doc.a.insert(_1b.id, "d".to_string());

        assert_eq!(
            base1.doc.view().into_json(),
            json!({
                "a": ["a", "b"],
            })
        );

        // as _1b hasn't been delivered to base2 yet
        assert_eq!(
            base2.doc.view().into_json(),
            json!({
                "a": ["c"],
            })
        );

        base2.apply(_1b.export());
        base2.apply(_1a.export());
        base1.apply(_2d.export());
        base1.apply(_2c.export());
        assert_eq!(base1.doc.view().into_json(), base2.doc.view().into_json());
    }

    #[test]
    fn test_causal_field_dependency() {
        #[add_crdt_fields]
        #[derive(Debug, Clone, CRDT)]
        struct Item<'t> {
            name: LWWRegisterCRDT<'t, String>,
            soulbound: LWWRegisterCRDT<'t, bool>,
        }

        #[add_crdt_fields]
        #[derive(Debug, Clone, CRDT)]
        struct Player<'t> {
            inventory: ListCRDT<'t, Item<'t>>,
            balance: LWWRegisterCRDT<'t, f64>,
        }

        // require balance update to happen before inventory update
        let kp1 = make_keypair();
        let kp2 = make_keypair();
        let mut base1 = BaseCRDT::<Player>::new(&kp1);
        let mut base2 = BaseCRDT::<Player>::new(&kp2);

        let _add_money = base1.doc.balance.set(5000.0);
        let _spend_money = base1.doc.balance.set(3000.0);
        let sword: Value = json!({
            "name": "Sword",
            "soulbound": true,
        })
        .into();
        let _new_inventory_item = base1.doc.inventory.insert_idx(0, sword);
        assert_eq!(
            base1.doc.view().into_json(),
            json!({
                "balance": 3000.0,
                "inventory": [
                    {
                        "name": "Sword",
                        "soulbound": true
                    }
                ]
            })
        );
    }

    #[test]
    fn test_2d_grid() {
        #[add_crdt_fields]
        #[derive(Debug, Clone, CRDT)]
        struct Todo<'t> {
            grid: ListCRDT<'t, ListCRDT<'t, LWWRegisterCRDT<'t, bool>>>,
        }
    }

    #[test]
    fn test_nested_ops() {
        #[add_crdt_fields]
        #[derive(Debug, Clone, CRDT)]
        struct Todo<'t> {
            name: LWWRegisterCRDT<'t, String>,
            due: LWWRegisterCRDT<'t, String>,
            done: LWWRegisterCRDT<'t, bool>,
            tags: ListCRDT<'t, String>,
        }

        #[add_crdt_fields]
        #[derive(Debug, Clone, CRDT)]
        struct Schedule<'t> {
            items: ListCRDT<'t, Todo<'t>>,
        }
    }
}
