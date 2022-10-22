use bft_json_crdt::list_crdt::ListCRDT;
use bft_json_crdt::op::{OpID, ROOT_ID};
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

#[test]
fn test_editing_trace() {
    let t = get_trace();
    let mut list = ListCRDT::<char>::new();
    let mut ops: Vec<OpID> = Vec::new();
    ops.push(ROOT_ID);
    let start = PreciseTime::now();
    let edits = t.edits;
    let mut i = 0;
    for op in edits {
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
                println!("took {:?} to run {i} ops", runtime_sec);
            }
            _ => {}
        };
        i += 1;
    }

    let end = PreciseTime::now();
    let runtime_sec = start.to(end);
    println!("took {:?} to finish", runtime_sec);
    let result = list.iter().collect::<String>();
    let expected = t.final_text;
    assert_eq!(result.len(), expected.len());
    assert_eq!(result, expected);
    assert!(false);
}
