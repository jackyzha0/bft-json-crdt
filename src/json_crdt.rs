use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
};

use crate::{
    debug::{debug_op_on_primitive, DebugView},
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

/// Anything that can be nested in a JSON CRDT
pub trait CRDTNode: CRDTNodeFromValue + Hashable + Clone {
    /// Create a new CRDT of this type
    fn new(id: AuthorID, path: Vec<PathSegment>) -> Self;
    /// Apply an operation to this CRDT, forwarding if necessary
    fn apply(&mut self, op: Op<Value>) -> OpState;
    /// Get a JSON representation of the value in this node
    fn view(&self) -> Value;
}

/// Enum representing possible outcomes of applying an operation to a CRDT
#[derive(Debug, PartialEq)]
pub enum OpState {
    /// Operation applied successfully
    Ok,
    /// Tried to apply an operation to a non-CRDT primative (i.e. f64, bool, etc.)
    /// If you would like a mutable primitive, wrap it in a [`LWWRegisterCRDT`]
    ErrApplyOnPrimitive,
    /// Tried to apply an operation to a static struct CRDT
    /// If you would like a mutable object, use a [`Value`]
    ErrApplyOnStruct,
    /// Tried to apply an operation that contains content of the wrong type.
    /// In other words, the content cannot be coerced to the CRDT at the path specified.
    ErrMismatchedType,
    /// The signed digest of the message did not match the claimed author of the message.
    /// This can happen if the message was tampered with during delivery
    ErrDigestMismatch,
    /// The hash of the message did not match the contents of the mesage.
    /// This can happen if the author tried to perform an equivocation attack by creating an
    /// operation and modifying it has already been created
    ErrHashMismatch,
    /// Tried to apply an operation to a non-existent path. The author may have forgotten to attach
    /// a causal dependency
    ErrPathMismatch,
    /// Trying to modify/delete the sentinel (zero-th) node element that is used for book-keeping
    ErrListApplyToEmpty,
    /// We have not received all of the causal dependencies of this operation. It has been queued
    /// up and will be executed when its causal dependencies have been delivered
    MissingCausalDependencies,
}

/// The following types can be used as a 'terminal' type in CRDTs
pub trait MarkPrimitive: Into<Value> + Default {}
impl MarkPrimitive for bool {}
impl MarkPrimitive for i32 {}
impl MarkPrimitive for i64 {}
impl MarkPrimitive for f64 {}
impl MarkPrimitive for char {}
impl MarkPrimitive for String {}
impl MarkPrimitive for Value {}

/// Implement CRDTNode for non-CRDTs
/// This is a stub implementation so most functions don't do anything/log an error
impl<T> CRDTNode for T
where
    T: CRDTNodeFromValue + MarkPrimitive + Hashable + Clone,
{
    fn apply(&mut self, _op: Op<Value>) -> OpState {
        OpState::ErrApplyOnPrimitive
    }

    fn view(&self) -> Value {
        self.to_owned().into()
    }

    fn new(_id: AuthorID, _path: Vec<PathSegment>) -> Self {
        debug_op_on_primitive(_path);
        Default::default()
    }
}

/// The base struct for a JSON CRDT. Allows for declaring causal
/// dependencies across fields. It only accepts messages of [`SignedOp`] for BFT.
pub struct BaseCRDT<T: CRDTNode> {
    /// Public key of this CRDT
    pub id: AuthorID,

    /// Internal base CRDT
    pub doc: T,

    /// In a real world scenario, this would be a proper hashgraph that allows for
    /// efficient reconciliation of missing dependencies. We naively keep a hashset
    /// of messages we've seen (represented by their [`SignedDigest`]).
    received: HashSet<SignedDigest>,
    message_q: HashMap<SignedDigest, Vec<SignedOp>>,
}

/// An [`Op<Value>`] with a few bits of extra metadata
#[derive(Clone)]
pub struct SignedOp {
    // Note that this can be different from the author of the inner op as the inner op could have been created
    // by a different person
    author: AuthorID,
    /// Signed hash using priv key of author. Effectively [`OpID`] Use this as the ID to figure out what has been delivered already
    pub signed_digest: SignedDigest,
    pub inner: Op<Value>,
    /// List of causal dependencies
    pub depends_on: Vec<SignedDigest>,
}

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

    /// Sign this digest with the given keypair. Shouldn't need to be called manually,
    /// just use [`SignedOp::from_op`] instead
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

    /// Sign a normal op and add all the needed metadata
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

impl<T: CRDTNode + DebugView> BaseCRDT<T> {
    /// Crease a new BaseCRDT of the given type. Multiple BaseCRDTs
    /// can be created from a single keypair but you are responsible for 
    /// routing messages to the right BaseCRDT. Usually you should just make a single 
    /// struct that contains all the state you need
    pub fn new(keypair: &Ed25519KeyPair) -> Self {
        let id = keypair.public().0.to_bytes();
        Self {
            id,
            doc: T::new(id, vec![]),
            received: HashSet::new(),
            message_q: HashMap::new(),
        }
    }

    /// Apply a signed operation to this BaseCRDT, verifying integrity and routing to the right
    /// nested CRDT
    pub fn apply(&mut self, op: SignedOp) -> OpState {
        self.log_try_apply(&op);

        #[cfg(feature = "bft")]
        if !op.is_valid_digest() {
            self.debug_digest_failure(op);
            return OpState::ErrDigestMismatch;
        }

        let op_id = op.signed_digest;
        if !op.depends_on.is_empty() {
            for origin in &op.depends_on {
                if !self.received.contains(origin) {
                    self.log_missing_causal_dep(origin);
                    self.message_q.entry(*origin).or_default().push(op);
                    return OpState::MissingCausalDependencies;
                }
            }
        }

        // apply
        self.log_actually_apply(&op);
        let status = self.doc.apply(op.inner);
        self.debug_view();
        self.received.insert(op_id);
        
        // apply all of its causal dependents if there are any
        let dependent_queue = self.message_q.remove(&op_id);
        if let Some(mut q) = dependent_queue {
            for dependent in q.drain(..) {
                self.apply(dependent);
            }
        }
        status
    }
}

/// An enum representing a JSON value
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

/// Allow easy conversion to and from serde's JSON format. This allows us to use the [`json!`]
/// macro
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
    pub fn into_json(self) -> serde_json::Value {
        self.into()
    }
}

/// Conversions from primitive types to [`Value`]
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

/// Fallibly create a CRDT Node from a JSON Value 
pub trait CRDTNodeFromValue: Sized {
    fn node_from(value: Value, id: AuthorID, path: Vec<PathSegment>) -> Result<Self, String>;
}

/// Fallibly cast a JSON Value into a CRDT Node 
pub trait IntoCRDTNode<T>: Sized {
    fn into_node(self, id: AuthorID, path: Vec<PathSegment>) -> Result<T, String>;
}

/// [`CRDTNodeFromValue`] implies [`IntoCRDTNode<T>`]
impl<T> IntoCRDTNode<T> for Value
where
    T: CRDTNodeFromValue,
{
    fn into_node(self, id: AuthorID, path: Vec<PathSegment>) -> Result<T, String> {
        T::node_from(self, id, path)
    }
}

/// Trivial conversion from Value to Value as CRDTNodeFromValue
impl CRDTNodeFromValue for Value {
    fn node_from(value: Value, _id: AuthorID, _path: Vec<PathSegment>) -> Result<Self, String> {
        Ok(value)
    }
}

/// Conversions from primitives to CRDTs
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
        json_crdt::{add_crdt_fields, BaseCRDT, CRDTNode, IntoCRDTNode, OpState, Value},
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

        assert_eq!(base2.apply(_1_a_1), OpState::Ok);
        assert_eq!(base2.apply(_1_b_1), OpState::Ok);
        assert_eq!(base1.apply(_2_a_1), OpState::Ok);
        assert_eq!(base1.apply(_2_a_2), OpState::Ok);
        assert_eq!(base1.apply(_2_c_1), OpState::Ok);

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

        assert_eq!(base2.apply(_1b), OpState::MissingCausalDependencies);
        assert_eq!(base2.apply(_1a), OpState::Ok);
        assert_eq!(base1.apply(_2d), OpState::Ok);
        assert_eq!(base1.apply(_2c), OpState::Ok);
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
        assert_eq!(
            base2.apply(_new_inventory_item),
            OpState::MissingCausalDependencies
        );
        assert_eq!(
            base2.apply(_spend_money),
            OpState::MissingCausalDependencies
        );
        assert_eq!(base2.apply(_add_money), OpState::Ok);
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
        let construct2 = base1.doc.grid.insert_idx(1, row1).sign(&kp1);

        assert_eq!(base2.apply(construct1), OpState::Ok);
        assert_eq!(base2.apply(construct2.clone()), OpState::Ok);

        assert_eq!(base1.doc.view().into_json(), base2.doc.view().into_json());
        assert_eq!(
            base1.doc.view().into_json(),
            json!({
                "grid": [[true, false], [false, true]]
            })
        );

        let set1 = base1.doc.grid[0][0].set(false).sign(&kp1);
        let set2 = base2.doc.grid[1][1].set(false).sign(&kp2);
        assert_eq!(base1.apply(set2), OpState::Ok);
        assert_eq!(base2.apply(set1), OpState::Ok);

        assert_eq!(base1.doc.view().into_json(), base2.doc.view().into_json());
        assert_eq!(
            base1.doc.view().into_json(),
            json!({
                "grid": [[false, false], [false, false]]
            })
        );

        let topright = base1.doc.grid[0].id_at(1).unwrap();
        base1.doc.grid[0].delete(topright);
        assert_eq!(
            base1.doc.view().into_json(),
            json!({
                "grid": [[false], [false, false]]
            })
        );

        base1.doc.grid.delete(construct2.id());
        assert_eq!(
            base1.doc.view().into_json(),
            json!({
                "grid": [[false]]
            })
        );
    }

    #[test]
    fn test_arb_json() {
        #[add_crdt_fields]
        #[derive(Clone, CRDTNode)]
        struct Test {
            reg: LWWRegisterCRDT<Value>,
        }

        let kp1 = make_keypair();
        let mut base1 = BaseCRDT::<Test>::new(&kp1);

        let base_val: Value = json!({
            "a": true,
            "b": "asdf",
            "c": {
                "d": [],
                "e": [ false ]
            }
        })
        .into();
        base1.doc.reg.set(base_val).sign(&kp1);
        assert_eq!(
            base1.doc.view().into_json(),
            json!({
                "reg": {
                    "a": true,
                    "b": "asdf",
                    "c": {
                        "d": [],
                        "e": [ false ]
                    }
                }
            })
        );
    }

    #[test]
    fn test_wrong_json_types() {
        #[add_crdt_fields]
        #[derive(Clone, CRDTNode)]
        struct Nested {
            list: ListCRDT<f64>,
        }

        #[add_crdt_fields]
        #[derive(Clone, CRDTNode)]
        struct Test {
            reg: LWWRegisterCRDT<bool>,
            strct: ListCRDT<Nested>,
        }

        let key = make_keypair();
        let mut crdt = BaseCRDT::<Test>::new(&key);

        // wrong type should not go through
        crdt.doc.reg.set(32);
        assert_eq!(crdt.doc.reg.view(), json!(null).into());
        crdt.doc.reg.set(true);
        assert_eq!(crdt.doc.reg.view(), json!(true).into());

        // set nested
        let mut list_view: Value = crdt.doc.strct.view().into();
        assert_eq!(list_view, json!([]).into());

        // only keeps actual numbers
        let list: Value = json!({"list": [0, 123, -0.45, "char", []]}).into();
        crdt.doc.strct.insert_idx(0, list);
        list_view = crdt.doc.strct.view().into();
        assert_eq!(list_view, json!([{ "list": [0, 123, -0.45]}]).into());
    }
}
