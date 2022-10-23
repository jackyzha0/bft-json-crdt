use bft_json_crdt::{
    list_crdt::ListCRDT,
    op::{Op, ROOT_ID},
};

// What is potentially Byzantine behaviour?
// 1. send valid updates
// 2. send a mix of valid and invalid updates
//  a) messages with duplicate ID (attempt to overwrite old entries)
//  b) send incorrect sequence number to multiple nodes (which could lead to divergent state) -- this is called equivocation
//  c) ‘forge’ updates from another author (could happen when forwarding valid messages from peers)
//  d) incorrectly setting origin
// 3. send malformed updates (e.g. missing fields)
//      this we don't test as we assume transport layer only allows valid messages
// 4. overwhelm message queue by sending many updates far into the future
//      also untestested! currently i keep an unbounded message queue

// case 2a
#[test]
fn test_byzantine_overwrite() {
    let mut list = ListCRDT::<char>::new();
    let _a = list.insert(ROOT_ID, 'a');
    let _b = list.insert(_a.id, 'b');

    // make a fake operation with same id as _b
    let fake_op = Op {
        content: Some('c'),
        .._b
    };

    // also try modifying the sequence number
    let fake_op_seq = Op {
        seq: 99,
        is_deleted: true,
        .._b
    };

    list.apply(fake_op);
    list.apply(fake_op_seq);

    // make sure it doesnt accept fake operation but real one still goes through
    assert_eq!(list.view(), vec![&'a', &'b']);
}

// case 2b
// #[test]
// fn test_equivocation() {
//     let mut rng = rand::thread_rng();
//     let mut list1 = ListCRDT::<char>::new();
//     let mut list2 = ListCRDT::<char>::new();
//
//     let mut fake_op = Op {
//         author: rng.gen(),
//         seq: 0,
//         id: ROOT_ID,
//         origin: ROOT_ID,
//         is_deleted: false,
//         content: Some('a'),
//     };
//     fake_op.id = fake_op.hash();
//     let mut op1 = fake_op.clone();
//     op1.seq = 5;
//     let mut op2 = fake_op.clone();
//     op2.seq = 3;
//
//     list1.apply(op1);
//     list2.apply(op2);
//
//     assert_eq!(list1.view().len(), 0);
//     assert_eq!(list2.view().len(), 0);
// }
