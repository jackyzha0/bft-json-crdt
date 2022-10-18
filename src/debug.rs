use std::{collections::HashMap, fmt::Display};

use crate::{
    list_crdt::ListCRDT,
    op::{AuthorID, Op, OpID, ROOT_ID},
};
use colored::Colorize;
use random_color::{Luminosity, RandomColor};

const ENABLE_LOGGING: bool = false;

fn author_to_hex(author: AuthorID) -> String {
    format!("{:#x}", author).to_string()
}

pub fn display_op_id(op: OpID) -> String {
    let [r, g, b] = RandomColor::new()
        .luminosity(Luminosity::Light)
        .seed(op.0 as u32 + 4)
        .to_rgb_array();
    format!(
        "[{},{}]",
        author_to_hex(op.0).bold().truecolor(r, g, b),
        op.1.to_string().yellow()
    )
}

pub fn display_author(author: AuthorID) -> String {
    let [r, g, b] = RandomColor::new()
        .luminosity(Luminosity::Light)
        .seed(author as u32 + 4)
        .to_rgb_array();
    format!(" {} ", author_to_hex(author))
        .black()
        .on_truecolor(r, g, b)
        .to_string()
}

impl<T> ListCRDT<T>
where
    T: Display + Clone + Eq,
{
    pub fn log_ops(&self, highlight: Option<OpID>) {
        if !ENABLE_LOGGING {
            return;
        }

        let mut lines = Vec::<String>::new();

        // do in-order traversal
        let res: Vec<&Op<T>> = self.ops.iter().collect();
        if res.len() == 0 {
            println!("{}", "[empty]".to_string());
        }

        // figure out parent-child hierarchies from origins
        let mut parent_child_map: HashMap<OpID, Vec<OpID>> = HashMap::new();
        for op in &res {
            let children = parent_child_map.entry(op.origin).or_insert(Vec::new());
            children.push(op.id);
        }

        let is_last = |op: &Op<T>| -> bool {
            if op.id == ROOT_ID {
                return true;
            }
            if let Some(children) = parent_child_map.get(&op.origin) {
                return *children.last().unwrap() == op.id;
            }
            false
        };

        // make stack of origins
        let mut stack: Vec<(OpID, &str)> = Vec::new();
        stack.push((ROOT_ID, ""));
        let mut prev = None;
        for op in &res {
            let origin_idx = self.find(op.origin).unwrap();
            let origin = &res[origin_idx];
            let origin_id = origin.id;
            if let Some(prev) = prev {
                if origin_id == prev {
                    // went down one layer, add to stack
                    let stack_prefix_char = if is_last(&origin) { "  " } else { "│ " };
                    stack.push((prev, stack_prefix_char));
                }
            }

            // pop back up until we reach the right origin
            while stack.last().unwrap().0 != origin_id {
                stack.pop();
            }

            let cur_char = if is_last(op) { "╰─" } else { "├─" };
            let prefixes = stack.iter().map(|s| s.1).collect::<Vec<_>>().join("");
            let highlight_text = if highlight.is_some() && highlight.unwrap() == op.id {
                if op.is_deleted {
                    "<- deleted".bold().red()
                } else {
                    "<- inserted".bold().green()
                }
                .to_string()
            } else {
                "".to_string()
            };

            let content = if op.id == ROOT_ID {
                "root".blue().bold().to_string()
            } else {
                op.content
                    .as_ref()
                    .map_or("[empty]".to_string(), |c| c.to_string())
            };
            if op.is_deleted {
                lines.push(format!(
                    "{}{}{} {} {}",
                    prefixes,
                    cur_char,
                    display_op_id(op.id),
                    content.strikethrough().red(),
                    highlight_text
                ));
            } else {
                lines.push(format!(
                    "{}{}{} {} {}",
                    prefixes,
                    cur_char,
                    display_op_id(op.id),
                    content,
                    highlight_text
                ));
            }
            prev = Some(op.id);
        }

        // full string
        let flat = format!(
            "{}",
            self.iter()
                .map(|t| t.to_string())
                .collect::<Vec<_>>()
                .join("")
        );
        lines.push(format!("Flattened result: {}", flat));
        println!("{}", lines.join("\n"));
    }

    pub fn log_apply(&self, op: &Op<T>) {
        if !ENABLE_LOGGING {
            return;
        }

        if op.is_deleted {
            println!(
                "{} Performing a delete of {}@{}",
                display_author(self.our_id),
                display_op_id(op.id),
                op.sequence_num(),
            );
            return;
        }

        println!(
            "{} Performing an insert of {}@{}: '{}' after {}",
            display_author(self.our_id),
            display_op_id(op.id),
            op.sequence_num(),
            op.content.as_ref().unwrap(),
            display_op_id(op.origin)
        );
    }
}
