use super::{node::{ROOT_ID, AuthorID}, tree::SplayTree};
use crate::splay::node::{Node, OpID};
use colored::Colorize;
use random_color::{Luminosity, RandomColor};
use std::{collections::BTreeMap, fmt::Display};

pub fn display_op(op: OpID) -> String {
    let [r, g, b] = RandomColor::new()
        .luminosity(Luminosity::Light)
        .seed(op.0 as u32 + 4)
        .to_rgb_array();
    format!(
        "[{},{}]",
        op.0.to_string().bold().truecolor(r, g, b),
        op.1.to_string().yellow()
    )
}

pub fn display_author(author: AuthorID) -> String {
    let [r, g, b] = RandomColor::new()
        .luminosity(Luminosity::Light)
        .seed(author as u32 + 4)
        .to_rgb_array();
    format!(" {} ", author).black().on_truecolor(r, g, b).to_string()
}

impl<'a, T> SplayTree<'a, T>
where
    T: Display,
{
    pub fn print(&self, highlight: Option<OpID>) -> String {
        let mut lines = Vec::<String>::new();

        // do in-order traversal
        let mut res = Vec::<&'a Node<'a, T>>::new();
        lines.push(format!(" {} {}", display_op(ROOT_ID), "Root".red().bold()));
        if let Some(root) = self.root() {
            root.traverse_collect(&mut res);
        } else {
            return "[empty]".to_string();
        }

        // figure out parent-child hierarchies from origins
        let mut parent_child_map: BTreeMap<OpID, Vec<OpID>> = BTreeMap::new();
        for node in &res {
            let origin_id = node.origin.get().unwrap().id;
            let children = parent_child_map.entry(origin_id).or_insert(Vec::new());
            children.push(node.id);
        }

        let is_last = |node: &Node<T>| -> bool {
            let origin = node.origin.get();
            if origin.is_none() {
                return true;
            }
            let origin_id = origin.unwrap().id;
            if let Some(children) = parent_child_map.get(&origin_id) {
                return *children.last().unwrap() == node.id;
            }
            false
        };

        // make stack of origins
        let mut stack: Vec<(OpID, &str)> = Vec::new();
        // stack.push((ROOT_ID, ""));
        let mut prev = Some(ROOT_ID);
        for node in &res {
            let origin = node.origin.get().unwrap();
            let origin_id = origin.id;
            if let Some(prev) = prev {
                if origin_id == prev {
                    // went down one layer, add to stack
                    let stack_prefix_char = if is_last(origin) { "  " } else { "│ " };
                    stack.push((prev, stack_prefix_char));
                }
            }

            // pop back up until we reach the right origin
            while stack.last().unwrap().0 != origin_id {
                stack.pop();
            }

            let cur_char = if is_last(node) { "╰─" } else { "├─" };
            let prefixes = stack.iter().map(|s| s.1).collect::<Vec<_>>().join("");
            let highlight_text = if highlight.is_some() && highlight.unwrap() == node.id {
                "NEW!".bold().green().to_string()
            } else {
                "".to_string()
            };
            lines.push(format!(
                "{}{}{} {} {}",
                prefixes,
                cur_char,
                display_op(node.id),
                node.content.as_ref().unwrap(),
                highlight_text
            ));
            prev = Some(node.id);
        }

        // full string 
        let res = format!("{}", res.iter().map(|node| node.content.as_ref().unwrap().to_string()).collect::<Vec<_>>().join(" "));
        lines.push(format!("Flattened result: {}", res));
        lines.join("\n")
    }
}
