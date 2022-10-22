use bft_json_crdt::{
    list_crdt::ListCRDT,
    op::{Op, ROOT_ID},
};
use rand::Rng;

// What is potentially Byzantine behaviour?
// 1. send valid updates
// 2. send a mix of valid and invalid updates
//  a) messages with duplicate ID (attempt to overwrite old entries)
//  b) send incorrect sequence number to multiple nodes (which could lead to divergent state) -- this is called equivocation
//  c) ‘forge’ updates with a specific ID or author
//  d) incorrectly setting origin
// 3. send malformed updates (e.g. missing fields)
// 4. can modify actually valid messages from correct nodes when forwarding
// 5. overwhelm message queue by sending many updates far into the future

#[test]
fn test_modified_msg() {
    let mut rng = rand::thread_rng();
    let mut list = ListCRDT::<char>::new();
    let _a = list.insert(ROOT_ID, 'a');
    let _b = list.insert(_a.id, 'b');

    // make a fake operation with same id as _b
    let fake_op = Op {
        content: Some('c'),
        .._b
    };

    // create an actual update that could be real
    // with no id
    let mut fake_op_2 = Op {
        author: rng.gen(),
        seq: 0,
        id: ROOT_ID,
        origin: _b.id,
        is_deleted: false,
        content: Some('d'),
    };
    fake_op_2.id = fake_op_2.hash();

    list.apply(fake_op);
    list.apply(fake_op_2);

    // make sure it doesnt accept fake operation but real one still goes through
    assert_eq!(list.view(), vec![&'a', &'b', &'d']);
}

// case 2b
#[test]
fn test_equivocation() {
    let mut rng = rand::thread_rng();
    let mut list1 = ListCRDT::<char>::new();
    let mut list2 = ListCRDT::<char>::new();

    let mut fake_op = Op {
        author: rng.gen(),
        seq: 0,
        id: ROOT_ID,
        origin: ROOT_ID,
        is_deleted: false,
        content: Some('a'),
    };
    fake_op.id = fake_op.hash();
    let mut op1 = fake_op.clone();
    op1.seq = 5;
    let mut op2 = fake_op.clone();
    op2.seq = 3;

    list1.apply(op1);
    list2.apply(op2);
    
    assert_eq!(list1.view().len(), 0);
    assert_eq!(list2.view().len(), 0);
}

