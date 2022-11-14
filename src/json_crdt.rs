use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
};

use crate::{
    debug::{DebugView, debug_op_on_primitive},
    keypair::{sha256, sign, AuthorID, SignedDigest},
    list_crdt::ListCRDT,
    lww_crdt::LWWRegisterCRDT,
    op::{print_hex, print_path, Hashable, Op, OpID, PathSegment},
};
pub use bft_crdt_derive::*;
use fastcrypto::{
    ed25519::{Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature},
    traits::{KeyPair, ToFromBytes},
    Verifier,
};

// Anything that can be nested in a JSON CRDT
pub trait CRDTNode: CRDTNodeFromValue + Hashable + Clone {
    fn apply(&mut self, op: Op<Value>);
    fn view(&self) -> Value;
    fn new(id: AuthorID, path: Vec<PathSegment>) -> Self;
}

/// implement CRDTNode for non-CRDTs
pub trait MarkPrimitive: Into<Value> + Default {}
impl MarkPrimitive for bool {}
impl MarkPrimitive for i32 {}
impl MarkPrimitive for i64 {}
impl MarkPrimitive for f64 {}
impl MarkPrimitive for char {}
impl MarkPrimitive for String {}
impl MarkPrimitive for Value {}
impl<T> CRDTNode for T
where
    T: CRDTNodeFromValue + MarkPrimitive + Hashable + Clone,
{
    fn apply(&mut self, _op: Op<Value>) {
        debug_op_on_primitive(_op.path);
    }

    fn view(&self) -> Value {
        self.to_owned().into()
    }

    fn new(_id: AuthorID, _path: Vec<PathSegment>) -> Self {
        debug_op_on_primitive(_path);
        Default::default() 
    }
}

#[allow(dead_code)]
pub struct BaseCRDT<'a, T: CRDTNode> {
    pub id: AuthorID,
    keypair: &'a Ed25519KeyPair,
    pub doc: T,

    /// In a real world scenario, this would be a hashgraph
    received: HashSet<SignedDigest>,
    message_q: HashMap<SignedDigest, Vec<SignedOp>>,
}

#[derive(Clone)]
pub struct SignedOp {
    /// Effectively [`OpID`] Use this as the ID to figure out what has been delivered already
    pub author: AuthorID, // author of the op note that this can be different from
    // author of the inner op as inner op could have been created
    // by a different person
    pub signed_digest: SignedDigest, // signed hash using priv key of author
    pub inner: Op<Value>,
    pub depends_on: Vec<SignedDigest>,
}

#[allow(dead_code)]
impl SignedOp {
    pub fn id(&self) -> OpID {
        self.inner.id
    }

    pub fn author(&self) -> AuthorID {
        self.author
    }

    /// Creates a digest of the following fields. Any changes in the fields will change the signed digest
    ///  - id (hash of the following)
    ///    - origin
    ///    - author
    ///    - seq
    ///    - is_deleted
    ///  - path
    ///  - dependencies
    fn digest(&self) -> [u8; 32] {
        let path_string = print_path(self.inner.path.clone());
        let dependency_string = self
            .depends_on
            .iter()
            .map(print_hex)
            .collect::<Vec<_>>()
            .join("");
        let fmt_str = format!("{:?},{path_string},{dependency_string}", self.id());
        sha256(fmt_str)
    }

    fn sign_digest(&mut self, keypair: &Ed25519KeyPair) {
        self.signed_digest = sign(keypair, &self.digest()).sig.to_bytes()
    }

    /// Ensure digest was actually signed by the author it claims to be signed by
    pub fn is_valid_digest(&self) -> bool {
        let digest = Ed25519Signature::from_bytes(&self.signed_digest);
        let pubkey = Ed25519PublicKey::from_bytes(&self.author());
        match (digest, pubkey) {
            (Ok(digest), Ok(pubkey)) => pubkey.verify(&self.digest(), &digest).is_ok(),
            (_, _) => false,
        }
    }

    pub fn from_op<T: CRDTNode>(
        value: Op<T>,
        keypair: &Ed25519KeyPair,
        depends_on: Vec<SignedDigest>,
    ) -> Self {
        let author = keypair.public().0.to_bytes();
        let mut new = Self {
            inner: Op {
                content: value.content.map(|c| c.view()),
                origin: value.origin,
                author: value.author,
                seq: value.seq,
                path: value.path,
                is_deleted: value.is_deleted,
                id: value.id,
            },
            author,
            signed_digest: [0u8; 64],
            depends_on,
        };
        new.sign_digest(keypair);
        new
    }
}

#[allow(dead_code)]
impl<'a, T: CRDTNode + DebugView> BaseCRDT<'a, T> {
    pub fn new(keypair: &'a Ed25519KeyPair) -> Self {
        let id = keypair.public().0.to_bytes();
        Self {
            id,
            keypair,
            doc: T::new(id, vec![]),
            received: HashSet::new(),
            message_q: HashMap::new(),
        }
    }

    pub fn apply(&mut self, op: SignedOp) {
        self.log_try_apply(&op);

        #[cfg(feature = "bft")]
        if !op.is_valid_digest() {
            self.debug_digest_failure(op);
            return;
        }

        let op_id = op.signed_digest;
        if !op.depends_on.is_empty() {
            for origin in &op.depends_on {
                if !self.received.contains(origin) {
                    self.log_missing_causal_dep(origin);
                    self.message_q.entry(*origin).or_default().push(op);
                    return;
                }
            }
        }

        // apply all of its causal dependents if there are any
        self.log_actually_apply(&op);
        self.doc.apply(op.inner);
        self.debug_view();
        self.received.insert(op_id);
        let dependent_queue = self.message_q.remove(&op_id);
        if let Some(mut q) = dependent_queue {
            for dependent in q.drain(..) {
                self.apply(dependent);
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(HashMap<String, Value>),
}

impl Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Value::Null => "null".to_string(),
                Value::Bool(b) => b.to_string(),
                Value::Number(n) => n.to_string(),
                Value::String(s) => format!("\"{s}\""),
                Value::Array(arr) => {
                    if arr.len() > 1 {
                        format!(
                            "[\n{}\n]",
                            arr.iter()
                                .map(|x| format!("  {x}"))
                                .collect::<Vec<_>>()
                                .join(",\n")
                        )
                    } else {
                        format!(
                            "[ {} ]",
                            arr.iter()
                                .map(|x| x.to_string())
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    }
                }
                Value::Object(obj) => format!(
                    "{{ {} }}",
                    obj.iter()
                        .map(|(k, v)| format!("  \"{k}\": {v}"))
                        .collect::<Vec<_>>()
                        .join(",\n")
                ),
            }
        )
    }
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

impl From<bool> for Value {
    fn from(val: bool) -> Self {
        Value::Bool(val)
    }
}

impl From<i64> for Value {
    fn from(val: i64) -> Self {
        Value::Number(val as f64)
    }
}

impl From<i32> for Value {
    fn from(val: i32) -> Self {
        Value::Number(val as f64)
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

impl From<char> for Value {
    fn from(val: char) -> Self {
        Value::String(val.into())
    }
}

impl<T> From<Option<T>> for Value
where
    T: CRDTNode,
{
    fn from(val: Option<T>) -> Self {
        match val {
            Some(x) => x.view(),
            None => Value::Null,
        }
    }
}

impl<T> From<Vec<T>> for Value
where
    T: CRDTNode,
{
    fn from(value: Vec<T>) -> Self {
        Value::Array(value.iter().map(|x| x.view()).collect())
    }
}

pub trait CRDTNodeFromValue: Sized {
    fn node_from(value: Value, id: AuthorID, path: Vec<PathSegment>) -> Result<Self, String>;
}

pub trait IntoCRDTNode<T>: Sized {
    fn into_node(self, id: AuthorID, path: Vec<PathSegment>) -> Result<T, String>;
}

impl<T> IntoCRDTNode<T> for Value
where
    T: CRDTNodeFromValue,
{
    fn into_node(self, id: AuthorID, path: Vec<PathSegment>) -> Result<T, String> {
        T::node_from(self, id, path)
    }
}

impl CRDTNodeFromValue for Value {
    fn node_from(value: Value, _id: AuthorID, _path: Vec<PathSegment>) -> Result<Self, String> {
        Ok(value)
    }
}

impl CRDTNodeFromValue for bool {
    fn node_from(value: Value, _id: AuthorID, _path: Vec<PathSegment>) -> Result<Self, String> {
        if let Value::Bool(x) = value {
            Ok(x)
        } else {
            Err(format!("failed to convert {value:?} -> bool"))
        }
    }
}

impl CRDTNodeFromValue for f64 {
    fn node_from(value: Value, _id: AuthorID, _path: Vec<PathSegment>) -> Result<Self, String> {
        if let Value::Number(x) = value {
            Ok(x)
        } else {
            Err(format!("failed to convert {value:?} -> f64"))
        }
    }
}

impl CRDTNodeFromValue for i64 {
    fn node_from(value: Value, _id: AuthorID, _path: Vec<PathSegment>) -> Result<Self, String> {
        if let Value::Number(x) = value {
            Ok(x as i64)
        } else {
            Err(format!("failed to convert {value:?} -> f64"))
        }
    }
}

impl CRDTNodeFromValue for String {
    fn node_from(value: Value, _id: AuthorID, _path: Vec<PathSegment>) -> Result<Self, String> {
        if let Value::String(x) = value {
            Ok(x)
        } else {
            Err(format!("failed to convert {value:?} -> String"))
        }
    }
}

impl CRDTNodeFromValue for char {
    fn node_from(value: Value, _id: AuthorID, _path: Vec<PathSegment>) -> Result<Self, String> {
        if let Value::String(x) = value.clone() {
            x.chars().next().ok_or(format!(
                "failed to convert {value:?} -> char: found a zero-length string"
            ))
        } else {
            Err(format!("failed to convert {value:?} -> char"))
        }
    }
}

impl<T> CRDTNodeFromValue for LWWRegisterCRDT<T>
where
    T: CRDTNode,
{
    fn node_from(value: Value, id: AuthorID, path: Vec<PathSegment>) -> Result<Self, String> {
        let mut crdt = LWWRegisterCRDT::new(id, path);
        crdt.set(value);
        Ok(crdt)
    }
}

impl<T> CRDTNodeFromValue for ListCRDT<T>
where
    T: CRDTNode,
{
    fn node_from(value: Value, id: AuthorID, path: Vec<PathSegment>) -> Result<Self, String> {
        if let Value::Array(arr) = value {
            let mut crdt = ListCRDT::new(id, path);
            let result: Result<(), String> =
                arr.into_iter().enumerate().try_for_each(|(i, val)| {
                    crdt.insert_idx(i, val);
                    Ok(())
                });
            result?;
            Ok(crdt)
        } else {
            Err(format!("failed to convert {value:?} -> ListCRDT<T>"))
        }
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::{
        json_crdt::{add_crdt_fields, BaseCRDT, CRDTNode, IntoCRDTNode, Value},
        keypair::make_keypair,
        list_crdt::ListCRDT,
        lww_crdt::LWWRegisterCRDT,
        op::{print_path, ROOT_ID},
    };

    #[test]
    fn test_derive_basic() {
        #[add_crdt_fields]
        #[derive(Clone, CRDTNode)]
        struct Player {
            x: LWWRegisterCRDT<f64>,
            y: LWWRegisterCRDT<f64>,
        }

        let keypair = make_keypair();
        let crdt = BaseCRDT::<Player>::new(&keypair);
        assert_eq!(print_path(crdt.doc.x.path), "x");
        assert_eq!(print_path(crdt.doc.y.path), "y");
    }

    #[test]
    fn test_derive_nested() {
        #[add_crdt_fields]
        #[derive(Clone, CRDTNode)]
        struct Position {
            x: LWWRegisterCRDT<f64>,
            y: LWWRegisterCRDT<f64>,
        }

        #[add_crdt_fields]
        #[derive(Clone, CRDTNode)]
        struct Player {
            pos: Position,
            balance: LWWRegisterCRDT<f64>,
            messages: ListCRDT<String>,
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
        #[derive(Clone, CRDTNode)]
        struct Test {
            a: LWWRegisterCRDT<f64>,
            b: LWWRegisterCRDT<bool>,
            c: LWWRegisterCRDT<String>,
        }

        let kp1 = make_keypair();
        let kp2 = make_keypair();
        let mut base1 = BaseCRDT::<Test>::new(&kp1);
        let mut base2 = BaseCRDT::<Test>::new(&kp2);

        let _1_a_1 = base1.doc.a.set(3.0).sign(&kp1);
        let _1_b_1 = base1.doc.b.set(true).sign(&kp1);
        let _2_a_1 = base2.doc.a.set(1.5).sign(&kp2);
        let _2_a_2 = base2.doc.a.set(2.13).sign(&kp2);
        let _2_c_1 = base2.doc.c.set("abc".to_string()).sign(&kp2);

        assert_eq!(base1.doc.a.view(), json!(3.0).into());
        assert_eq!(base2.doc.a.view(), json!(2.13).into());
        assert_eq!(base1.doc.b.view(), json!(true).into());
        assert_eq!(base2.doc.c.view(), json!("abc").into());

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

        base2.apply(_1_a_1);
        base2.apply(_1_b_1);
        base1.apply(_2_a_1);
        base1.apply(_2_a_2);
        base1.apply(_2_c_1);

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
        #[derive(Clone, CRDTNode)]
        struct Test {
            a: ListCRDT<String>,
        }

        let kp1 = make_keypair();
        let kp2 = make_keypair();
        let mut base1 = BaseCRDT::<Test>::new(&kp1);
        let mut base2 = BaseCRDT::<Test>::new(&kp2);

        let _1a = base1.doc.a.insert(ROOT_ID, "a".to_string()).sign(&kp1);
        let _1b = base1.doc.a.insert(_1a.id(), "b".to_string()).sign(&kp1);
        let _2c = base2.doc.a.insert(ROOT_ID, "c".to_string()).sign(&kp2);
        let _2d = base2.doc.a.insert(_1b.id(), "d".to_string()).sign(&kp2);

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

        base2.apply(_1b);
        base2.apply(_1a);
        base1.apply(_2d);
        base1.apply(_2c);
        assert_eq!(base1.doc.view().into_json(), base2.doc.view().into_json());
    }

    #[test]
    fn test_causal_field_dependency() {
        #[add_crdt_fields]
        #[derive(Clone, CRDTNode)]
        struct Item {
            name: LWWRegisterCRDT<String>,
            soulbound: LWWRegisterCRDT<bool>,
        }

        #[add_crdt_fields]
        #[derive(Clone, CRDTNode)]
        struct Player {
            inventory: ListCRDT<Item>,
            balance: LWWRegisterCRDT<f64>,
        }

        let kp1 = make_keypair();
        let kp2 = make_keypair();
        let mut base1 = BaseCRDT::<Player>::new(&kp1);
        let mut base2 = BaseCRDT::<Player>::new(&kp2);

        // require balance update to happen before inventory update
        let _add_money = base1.doc.balance.set(5000.0).sign(&kp1);
        let _spend_money = base1
            .doc
            .balance
            .set(3000.0)
            .sign_with_dependencies(&kp1, vec![&_add_money]);

        let sword: Value = json!({
            "name": "Sword",
            "soulbound": true,
        })
        .into();
        let _new_inventory_item = base1
            .doc
            .inventory
            .insert_idx(0, sword)
            .sign_with_dependencies(&kp1, vec![&_spend_money]);

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

        // do it completely out of order
        base2.apply(_new_inventory_item);
        base2.apply(_spend_money);
        base2.apply(_add_money);
        assert_eq!(base1.doc.view().into_json(), base2.doc.view().into_json());
    }

    #[test]
    fn test_2d_grid() {
        #[add_crdt_fields]
        #[derive(Clone, CRDTNode)]
        struct Game {
            grid: ListCRDT<ListCRDT<LWWRegisterCRDT<bool>>>,
        }

        let kp1 = make_keypair();
        let kp2 = make_keypair();
        let mut base1 = BaseCRDT::<Game>::new(&kp1);
        let mut base2 = BaseCRDT::<Game>::new(&kp2);

        // init a 2d grid
        let row0: Value = json!([true, false]).into();
        let row1: Value = json!([false, true]).into();
        let construct1 = base1.doc.grid.insert_idx(0, row0).sign(&kp1);
        base1.debug_view();
        let construct2 = base1.doc.grid.insert_idx(1, row1).sign(&kp1);
        base1.debug_view();

        base2.apply(construct1);
        base2.apply(construct2);

        assert_eq!(base1.doc.view().into_json(), base2.doc.view().into_json());
        assert_eq!(
            base1.doc.view().into_json(),
            json!({
                "grid": [[true, false], [false, true]]
            })
        );

        let set1 = base1.doc.grid[0][0].set(false).sign(&kp1);
        let set2 = base2.doc.grid[1][1].set(false).sign(&kp2);
        base1.apply(set2);
        base2.apply(set1);

        assert_eq!(base1.doc.view().into_json(), base2.doc.view().into_json());
        assert_eq!(
            base1.doc.view().into_json(),
            json!({
                "grid": [[false, false], [false, false]]
            })
        );
    }

    #[test]
    fn test_arb_json() {
        #[add_crdt_fields]
        #[derive(Clone, CRDTNode)]
        struct Todo {
            reg: LWWRegisterCRDT<Value>,
        }
    }
}
