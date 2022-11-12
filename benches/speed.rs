#![feature(test)]

extern crate test;
use bft_json_crdt::{keypair::make_author, list_crdt::ListCRDT, op::Op, op::ROOT_ID};
use rand::seq::SliceRandom;
use test::Bencher;

#[bench]
fn bench_insert_1_000_root(b: &mut Bencher) {
    b.iter(|| {
        let mut list = ListCRDT::<i32>::new(make_author(1), vec![]);
        for i in 0..1_000 {
            list.insert(ROOT_ID, i);
        }
    })
}

#[bench]
fn bench_insert_1_000_linear(b: &mut Bencher) {
    b.iter(|| {
        let mut list = ListCRDT::<i32>::new(make_author(1), vec![]);
        let mut prev = ROOT_ID;
        for i in 0..1_000 {
            let op = list.insert(prev, i);
            prev = op.id;
        }
    })
}

#[bench]
fn bench_insert_many_agents_conflicts(b: &mut Bencher) {
    b.iter(|| {
        const N: u8 = 50;
        let mut rng = rand::thread_rng();
        let mut crdts: Vec<ListCRDT<usize>> = Vec::with_capacity(N as usize);
        let mut logs: Vec<Op<usize>> = Vec::new();
        for i in 0..N {
            let list = ListCRDT::new(make_author(i), vec![]);
            crdts.push(list);
            for _ in 0..5 {
                let op = crdts[i as usize].insert(ROOT_ID, i);
                logs.push(op);
            }
        }

        logs.shuffle(&mut rng);
        for op in logs {
            for c in &mut crdts {
                if op.author() != c.our_id {
                    c.apply(op.clone());
                }
            }
        }

        assert!(crdts.windows(2).all(|w| w[0].view() == w[1].view()));
    })
}
