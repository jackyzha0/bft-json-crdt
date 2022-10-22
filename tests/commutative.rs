use bft_json_crdt::{op::{Op, OpID, ROOT_ID}, list_crdt::ListCRDT};
use rand::{rngs::ThreadRng, seq::SliceRandom, Rng};

fn random_op<T: Clone>(arr: &Vec<Op<T>>, rng: &mut ThreadRng) -> OpID {
    arr.choose(rng).map(|op| op.id).unwrap_or(ROOT_ID)
}

#[test]
fn test_fuzz_commutative_property() {
    let mut rng = rand::thread_rng();
    let mut op_log = Vec::<Op<char>>::new();
    let mut op_log1 = Vec::<Op<char>>::new();
    let mut op_log2 = Vec::<Op<char>>::new();
    let mut l1 = ListCRDT::<char>::new();
    let mut l2 = ListCRDT::<char>::new();
    let mut chk = ListCRDT::<char>::new();
    for _ in 0..50 {
        let letter1: char = rng.gen_range(b'a', b'z') as char;
        let letter2: char = rng.gen_range(b'a', b'z') as char;
        let op1 = l1.insert(random_op(&op_log1, &mut rng), letter1);
        let op2 = l2.insert(random_op(&op_log2, &mut rng), letter2);
        op_log1.push(op1);
        op_log2.push(op2);
        op_log.push(op1);
        op_log.push(op2);
    }

    // shuffle ops
    op_log1.shuffle(&mut rng);
    op_log2.shuffle(&mut rng);

    // apply to each other
    for op in op_log1 {
        l2.apply(op);
        chk.apply(op);
    }
    for op in op_log2 {
        l1.apply(op);
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
    let mut op_log1 = Vec::<Op<char>>::new();
    let mut op_log2 = Vec::<Op<char>>::new();
    for _ in 0..50 {
        let letter1: char = rng.gen_range(b'a', b'z') as char;
        let letter2: char = rng.gen_range(b'a', b'z') as char;
        let op1 = l1.insert(random_op(&op_log, &mut rng), letter1);
        let op2 = l2.insert(random_op(&op_log, &mut rng), letter2);
        op_log1.push(op1);
        op_log2.push(op2);
    }

    for op in op_log1 {
        l2.apply(op);
        chk.apply(op);
    }
    for op in op_log2 {
        l1.apply(op);
        chk.apply(op);
    }

    let l1_doc = l1.view();
    let l2_doc = l2.view();
    let chk_doc = chk.view();
    assert_eq!(l1_doc, l2_doc);
    assert_eq!(l1_doc, chk_doc);
    assert_eq!(l2_doc, chk_doc);
}
