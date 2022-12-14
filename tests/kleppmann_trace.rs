use bft_json_crdt::keypair::make_author;
use bft_json_crdt::list_crdt::ListCrdt;
use bft_json_crdt::op::{OpId, ROOT_ID};
use std::{fs::File, io::Read};
use time::PreciseTime;

use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Edit {
    pos: usize,
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
    let fp = "./tests/edits.json";
    match File::open(fp) {
        Err(e) => panic!("Open edits.json failed: {:?}", e.kind()),
        Ok(mut file) => {
            let mut content: String = String::new();
            file.read_to_string(&mut content)
                .expect("Problem reading file");
            serde_json::from_str(&content).expect("JSON was not well-formatted")
        }
    }
}

/// Really large test to run Martin Kleppmann's
/// editing trace over his paper
/// Data source: https://github.com/automerge/automerge-perf
#[test]
fn test_editing_trace() {
    let t = get_trace();
    let mut list = ListCrdt::<char>::new(make_author(1), vec![]);
    let mut ops: Vec<OpId> = Vec::new();
    ops.push(ROOT_ID);
    let start = PreciseTime::now();
    let edits = t.edits;
    for (i, op) in edits.into_iter().enumerate() {
        let origin = ops[op.pos];
        if op.delete {
            let delete_op = list.delete(origin);
            ops.push(delete_op.id);
        } else {
            let new_op = list.insert(origin, op.content.unwrap());
            ops.push(new_op.id);
        }

        match i {
            10_000 | 100_000 => {
                let end = PreciseTime::now();
                let runtime_sec = start.to(end);
                println!("took {runtime_sec:?} to run {i} ops");
            }
            _ => {}
        };
    }

    let end = PreciseTime::now();
    let runtime_sec = start.to(end);
    println!("took {runtime_sec:?} to finish");
    let result = list.iter().collect::<String>();
    let expected = t.final_text;
    assert_eq!(result.len(), expected.len());
    assert_eq!(result, expected);
}
