use bft_json_crdt::{
    json_crdt::{add_crdt_fields, BaseCRDT, IntoCRDTNode, CRDTNode},
    keypair::make_keypair,
    list_crdt::ListCRDT,
    op::{Op, ROOT_ID}, lww_crdt::LWWRegisterCRDT,
};

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
#[derive(Clone, CRDTNode)]
struct ListExample {
    list: ListCRDT<char>,
}

#[add_crdt_fields]
#[derive(Clone, CRDTNode)]
struct Nested {
    a: Nested2
}

#[add_crdt_fields]
#[derive(Clone, CRDTNode)]
struct Nested2 {
    b: LWWRegisterCRDT<bool>
}

// case 2a + 2b
#[test]
fn test_equivocation() {
    let key = make_keypair();
    let mut crdt = BaseCRDT::<ListExample>::new(&key);
    let _a = crdt.doc.list.insert(ROOT_ID, 'a').sign(&key);
    let _b = crdt.doc.list.insert(_a.id(), 'b').sign(&key);

    // make a fake operation with same id as _b but different content
    let mut fake_op = _b.clone();
    fake_op.inner.content = Some('c'.into());

    // also try modifying the sequence number
    let mut fake_op_seq = _b;
    fake_op_seq.inner.seq = 99;
    fake_op_seq.inner.is_deleted = true;

    crdt.apply(fake_op);
    crdt.apply(fake_op_seq);

    // make sure it doesnt accept either of the fake operations
    assert_eq!(crdt.doc.list.view(), vec!['a', 'b']);
}

// case 2c
#[test]
fn test_forge_update() {
    let key = make_keypair();
    let mut crdt = BaseCRDT::<ListExample>::new(&key);
    let _a = crdt.doc.list.insert(ROOT_ID, 'a');

    let keypair = make_keypair(); // generate a new keypair as we dont have privkey of list.our_id
    let mut op = Op {
        origin: _a.id,
        author: crdt.doc.list.our_id, // pretend to be the owner of list
        content: Some('b'),
        path: vec![],
        seq: 1,
        is_deleted: false,
        id: ROOT_ID, // placeholder, to be generated
    };

    // this is a completely valid hash and digest, just signed by the wrong person
    // as keypair.public != list.public
    op.id = op.hash_to_id(); // we can't tell from op.hash() alone whether this op is valid or not
    let signed = op.sign(&keypair);

    crdt.apply(signed);

    // make sure it doesnt accept fake operation
    assert_eq!(crdt.doc.list.view(), vec!['a']);
}

// #[test]
// fn test_different_base() {
//
// }
//
// #[test]
// fn test_path_update() {
//     let key = make_keypair();
//     let mut crdt = BaseCRDT::<Nested>::new(&key);
//     let _a = crdt.doc.a.b.set('a');
//     let _true = crdt.doc.a.b.set(true);
//
//     let keypair = make_keypair(); // generate a new keypair as we dont have privkey of list.our_id
//     let mut op = Op {
//         origin: _a.id,
//         author: crdt.doc.list.our_id, // pretend to be the owner of list
//         content: Some('b'),
//         path: vec![],
//         seq: 1,
//         is_deleted: false,
//         id: ROOT_ID, // placeholder, to be generated
//     };
//
//     // this is a completely valid hash and digest, just signed by the wrong person
//     // as keypair.public != list.public
//     op.id = op.hash_to_id(); // we can't tell from op.hash() alone whether this op is valid or not
//     let signed = op.sign(&keypair);
//
//     crdt.apply(signed);
//
//     // make sure it doesnt accept fake operation
//     assert_eq!(crdt.doc.list.view(), vec!['a']);
// }
