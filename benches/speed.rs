#![feature(test)]

extern crate test;
use bft_json_crdt::{keypair::make_keypair, list_crdt::ListCRDT, op::Op, op::ROOT_ID};
use fastcrypto::ed25519::Ed25519KeyPair;
use rand::seq::SliceRandom;
use test::Bencher;

#[bench]
fn bench_insert_1_000_root(b: &mut Bencher) {
    b.iter(|| {
        let key = make_keypair();
        let mut list = ListCRDT::new(&key, vec![]);
        for i in 0..1_000 {
            list.insert(ROOT_ID, i);
        }
    })
}

#[bench]
fn bench_insert_1_000_linear(b: &mut Bencher) {
    b.iter(|| {
        let key = make_keypair();
        let mut list = ListCRDT::new(&key, vec![]);
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
        const N: usize = 50;
        let mut rng = rand::thread_rng();
        let mut keys: Vec<Ed25519KeyPair> = Vec::with_capacity(N);
        // generate all of our keys
        (0..N).for_each(|i| keys[i] = make_keypair());

        let mut crdts: Vec<ListCRDT<usize>> = Vec::with_capacity(N);
        let mut logs: Vec<Op<usize>> = Vec::new();
        for i in 0..N {
            let list = ListCRDT::new(&keys[i], vec![]);
            crdts.push(list);
            for _ in 0..5 {
                let op = crdts[i].insert(ROOT_ID, i);
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
