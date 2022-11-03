use bft_json_crdt::{
    keypair::{make_keypair, sign},
    list_crdt::ListCRDT,
    op::{Op, ROOT_ID},
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
//      also untestested! currently i keep an unbounded message queue
// 5. block actual messages from honest actors (eclipse attack)

// case 2a + 2b
#[test]
fn test_equivocation() {
    let key = make_keypair();
    let mut list = ListCRDT::<char>::new(&key, vec![]);
    let _a = list.insert(ROOT_ID, 'a');
    let _b = list.insert(_a.id, 'b');

    // make a fake operation with same id as _b
    let fake_op = Op {
        content: Some('c'),
        .._b.clone()
    };

    // also try modifying the sequence number
    let fake_op_seq = Op {
        seq: 99,
        is_deleted: true,
        .._b
    };

    list.apply(fake_op);
    list.apply(fake_op_seq);

    // make sure it doesnt accept either of the fake operations
    assert_eq!(list.view(), vec![&'a', &'b']);
}


// case 2c
#[test]
fn test_forge_update() {
    // this implicity generates its own keypair
    // its public key is stored as list.our_id
    let key = make_keypair();
    let mut list = ListCRDT::<char>::new(&key, vec![]);
    let _a = list.insert(ROOT_ID, 'a');

    let keypair = make_keypair(); // generate a new keypair as we dont have privkey of list.our_id
    let mut op = Op {
        origin: _a.id,
        author: list.our_id, // pretend to be the owner of list
        content: Some('b'),
        path: vec![],
        seq: 1,
        is_deleted: false,
        id: ROOT_ID, // placeholder, to be generated
        signed_digest: [0u8; 64], // placeholder, to be generated
    };

    // this is a completely valid hash and digest, just signed by the wrong person
    // as keypair.public != list.public
    op.id = op.hash(); // we can't tell from op.hash() alone whether this op is valid or not
    op.signed_digest = sign(&keypair, &op.id).sig.to_bytes();

    list.apply(op);

    // make sure it doesnt accept fake operation
    assert_eq!(list.view(), vec![&'a']);
}

