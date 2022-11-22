use bft_json_crdt::{
    keypair::make_author,
    list_crdt::ListCrdt,
    op::{Op, OpId, ROOT_ID}, json_crdt::{CrdtNode, Value},
};
use rand::{rngs::ThreadRng, seq::SliceRandom, Rng};

fn random_op<T: CrdtNode>(arr: &Vec<Op<T>>, rng: &mut ThreadRng) -> OpId {
    arr.choose(rng).map(|op| op.id).unwrap_or(ROOT_ID)
}

const TEST_N: usize = 100;

#[test]
fn test_list_fuzz_commutative() {
    let mut rng = rand::thread_rng();
    let mut op_log = Vec::<Op<Value>>::new();
    let mut op_log1 = Vec::<Op<Value>>::new();
    let mut op_log2 = Vec::<Op<Value>>::new();
    let mut l1 = ListCrdt::<char>::new(make_author(1), vec![]);
    let mut l2 = ListCrdt::<char>::new(make_author(2), vec![]);
    let mut chk = ListCrdt::<char>::new(make_author(3), vec![]);
    for _ in 0..TEST_N {
        let letter1: char = rng.gen_range(b'a'..=b'z') as char;
        let letter2: char = rng.gen_range(b'a'..=b'z') as char;
        let op1 = if rng.gen_bool(4.0 / 5.0) {
            l1.insert(random_op(&op_log1, &mut rng), letter1)
        } else {
            l1.delete(random_op(&op_log1, &mut rng))
        };
        let op2 = if rng.gen_bool(4.0 / 5.0) {
            l2.insert(random_op(&op_log2, &mut rng), letter2)
        } else {
            l2.delete(random_op(&op_log2, &mut rng))
        };
        op_log1.push(op1.clone());
        op_log2.push(op2.clone());
        op_log.push(op1.clone());
        op_log.push(op2.clone());
    }

    // shuffle ops
    op_log1.shuffle(&mut rng);
    op_log2.shuffle(&mut rng);

    // apply to each other
    for op in op_log1 {
        l2.apply(op.clone());
        chk.apply(op.into());
    }
    for op in op_log2 {
        l1.apply(op.clone());
        chk.apply(op);
    }

    // ensure all equal
    let l1_doc = l1.view();
    let l2_doc = l2.view();
    let chk_doc = chk.view();
    assert_eq!(l1_doc, l2_doc);
    assert_eq!(l1_doc, chk_doc);
    assert_eq!(l2_doc, chk_doc);

    // now, allow cross mixing between both
    let mut op_log1 = Vec::<Op<Value>>::new();
    let mut op_log2 = Vec::<Op<Value>>::new();
    for _ in 0..TEST_N {
        let letter1: char = rng.gen_range(b'a'..=b'z') as char;
        let letter2: char = rng.gen_range(b'a'..=b'z') as char;
        let op1 = l1.insert(random_op(&op_log, &mut rng), letter1);
        let op2 = l2.insert(random_op(&op_log, &mut rng), letter2);
        op_log1.push(op1);
        op_log2.push(op2);
    }

    for op in op_log1 {
        l2.apply(op.clone());
        chk.apply(op);
    }
    for op in op_log2 {
        l1.apply(op.clone());
        chk.apply(op);
    }

    let l1_doc = l1.view();
    let l2_doc = l2.view();
    let chk_doc = chk.view();
    assert_eq!(l1_doc, l2_doc);
    assert_eq!(l1_doc, chk_doc);
    assert_eq!(l2_doc, chk_doc);
}
