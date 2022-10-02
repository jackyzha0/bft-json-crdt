#![feature(test)]

extern crate test;
use bft_json_crdt::{list_crdt::ListCRDT, op::Op, op::ROOT_ID};
use rand::{rngs::ThreadRng, seq::SliceRandom, Rng};
use test::Bencher;

#[bench]
fn bench_insert_1_000_root(b: &mut Bencher) {
    b.iter(|| {
        let mut list = ListCRDT::new(1);
        for i in 0..1_000 {
            list.insert(ROOT_ID, i);
        }
    })
}

#[bench]
fn bench_insert_1_000_linear(b: &mut Bencher) {
    b.iter(|| {
        let mut list = ListCRDT::new(1);
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
        const N: usize = 100;
        let mut rng = rand::thread_rng();
        let mut crdts: Vec<ListCRDT<char>> = Vec::with_capacity(N);
        let mut logs: Vec<Op<char>> = Vec::new();
        for i in 0..N {
            crdts.push(ListCRDT::new(rng.gen()));
            for _ in 0..5 {
                let op = crdts[i].insert(ROOT_ID, 'a');
                logs.push(op);
            }
        }

        logs.shuffle(&mut rng);
        for op in logs {
            for c in &mut crdts {
                if op.id.0 != c.our_id {
                    c.apply(op)
                }
            }
        }

        assert!(crdts.windows(2).all(|w| w[0].view() == w[1].view()));
    })
}
