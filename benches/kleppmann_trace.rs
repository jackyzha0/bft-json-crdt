#![feature(test)]

use bft_json_crdt::op::{OpID, ROOT_ID};
use std::{fs::File, io::Read};
extern crate test;
use bft_json_crdt::list_crdt::ListCRDT;
use test::Bencher;

use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Edit {
    idx: usize,
    delete: bool,
    #[serde(default)]
    content: Option<char>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Trace {
    final_text: String,
    edits: Vec<Edit>,
}

fn get_trace() -> Trace {
    let fp = "./benches/edits.json";
    match File::open(fp) {
        Err(e) => panic!("Open edits.json failed: {:?}", e.kind()),
        Ok(mut file) => {
            let mut content: String = String::new();
            file.read_to_string(&mut content).expect("Problem reading file");
            serde_json::from_str(&content).expect("JSON was not well-formatted")
        }
    }
}

#[bench]
fn bench_trace(b: &mut Bencher) {
    b.iter(|| {
        let t = get_trace();
        let mut list = ListCRDT::new(1);
        let mut ops: Vec<OpID> = Vec::new();
        ops.push(ROOT_ID);
        for op in t.edits.to_vec() {
            let origin = ops[op.idx - 1];
            if op.delete {
                list.delete(ops[op.idx]);
            } else {
                let new_op = list.insert(origin, op.content.unwrap());
                ops.push(new_op.id);
            }
        }
        assert_eq!(list.iter().collect::<String>(), t.final_text);
    })
}
