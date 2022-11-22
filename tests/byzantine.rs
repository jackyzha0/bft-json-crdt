use bft_json_crdt::{
    json_crdt::{add_crdt_fields, BaseCrdt, CrdtNode, IntoCrdtNode, OpState},
    keypair::make_keypair,
    list_crdt::ListCrdt,
    lww_crdt::LwwRegisterCrdt,
    op::{Op, PathSegment, ROOT_ID},
};
use serde_json::json;

// What is potentially Byzantine behaviour?
// 1. send valid updates
// 2. send a mix of valid and invalid updates
//  a) messages with duplicate ID (attempt to overwrite old entries)
//  b) send incorrect sequence number to multiple nodes (which could lead to divergent state) -- this is called equivocation
//  c) ‘forge’ updates from another author (could happen when forwarding valid messages from peers)
// 3. send malformed updates (e.g. missing fields)
//      this we don't test as we assume transport layer only allows valid messages
// 4. overwhelm message queue by sending many updates far into the future
//      also untestested! currently we keep an unbounded message queue
// 5. block actual messages from honest actors (eclipse attack)

#[add_crdt_fields]
#[derive(Clone, CrdtNode)]
struct ListExample {
    list: ListCrdt<char>,
}

// case 2a + 2b
#[test]
fn test_equivocation() {
    let key = make_keypair();
    let testkey = make_keypair();
    let mut crdt = BaseCrdt::<ListExample>::new(&key);
    let mut testcrdt = BaseCrdt::<ListExample>::new(&testkey);
    let _a = crdt.doc.list.insert(ROOT_ID, 'a').sign(&key);
    let _b = crdt.doc.list.insert(_a.id(), 'b').sign(&key);

    // make a fake operation with same id as _b but different content
    let mut fake_op = _b.clone();
    fake_op.inner.content = Some('c'.into());

    // also try modifying the sequence number
    let mut fake_op_seq = _b.clone();
    fake_op_seq.inner.seq = 99;
    fake_op_seq.inner.is_deleted = true;

    assert_eq!(crdt.apply(fake_op.clone()), OpState::ErrHashMismatch);
    assert_eq!(crdt.apply(fake_op_seq.clone()), OpState::ErrHashMismatch);

    assert_eq!(testcrdt.apply(fake_op_seq), OpState::ErrHashMismatch);
    assert_eq!(testcrdt.apply(fake_op), OpState::ErrHashMismatch);
    assert_eq!(testcrdt.apply(_a), OpState::Ok);
    assert_eq!(testcrdt.apply(_b), OpState::Ok);

    // make sure it doesnt accept either of the fake operations
    assert_eq!(crdt.doc.list.view(), vec!['a', 'b']);
    assert_eq!(crdt.doc.list.view(), testcrdt.doc.list.view());
}

// case 2c
#[test]
fn test_forge_update() {
    let key = make_keypair();
    let testkey = make_keypair();
    let mut crdt = BaseCrdt::<ListExample>::new(&key);
    let mut testcrdt = BaseCrdt::<ListExample>::new(&testkey);
    let _a = crdt.doc.list.insert(ROOT_ID, 'a').sign(&key);

    let fake_key = make_keypair(); // generate a new keypair as we dont have privkey of list.our_id
    let mut op = Op {
        origin: _a.inner.id,
        author: crdt.doc.id, // pretend to be the owner of list
        content: Some('b'),
        path: vec![PathSegment::Field("list".to_string())],
        seq: 1,
        is_deleted: false,
        id: ROOT_ID, // placeholder, to be generated
    };

    // this is a completely valid hash and digest, just signed by the wrong person
    // as keypair.public != list.public
    op.id = op.hash_to_id();
    let signed = op.sign(&fake_key);

    assert_eq!(crdt.apply(signed.clone()), OpState::ErrHashMismatch);
    assert_eq!(testcrdt.apply(signed), OpState::ErrHashMismatch);
    assert_eq!(testcrdt.apply(_a), OpState::Ok);

    // make sure it doesnt accept fake operation
    assert_eq!(crdt.doc.list.view(), vec!['a']);
}

#[add_crdt_fields]
#[derive(Clone, CrdtNode)]
struct Nested {
    a: Nested2,
}

#[add_crdt_fields]
#[derive(Clone, CrdtNode)]
struct Nested2 {
    b: LwwRegisterCrdt<bool>,
}

#[test]
fn test_path_update() {
    let key = make_keypair();
    let testkey = make_keypair();
    let mut crdt = BaseCrdt::<Nested>::new(&key);
    let mut testcrdt = BaseCrdt::<Nested>::new(&testkey);
    let mut _true = crdt.doc.a.b.set(true);
    _true.path = vec![PathSegment::Field("x".to_string())];
    let mut _false = crdt.doc.a.b.set(false);
    _false.path = vec![
        PathSegment::Field("a".to_string()),
        PathSegment::Index(_false.id),
    ];

    let signedtrue = _true.sign(&key);
    let signedfalse = _false.sign(&key);
    let mut signedfalsefakepath = signedfalse.clone();
    signedfalsefakepath.inner.path = vec![
        PathSegment::Field("a".to_string()),
        PathSegment::Field("b".to_string()),
    ];

    assert_eq!(testcrdt.apply(signedtrue), OpState::ErrPathMismatch);
    assert_eq!(testcrdt.apply(signedfalse), OpState::ErrPathMismatch);
    assert_eq!(testcrdt.apply(signedfalsefakepath), OpState::ErrDigestMismatch);

    // make sure it doesnt accept fake operation
    assert_eq!(crdt.doc.a.b.view(), json!(false).into());
    assert_eq!(testcrdt.doc.a.b.view(), json!(null).into());
}
