use crate::{
    json_crdt::{BaseCRDT, SignedOp, Value, CRDT},
    keypair::SignedDigest,
    list_crdt::ListCRDT,
    op::{Hashable, Op, OpID},
};

#[cfg(feature = "logging-base")]
use {
    crate::{
        keypair::{lsb_32, AuthorID},
        op::{ROOT_ID, print_hex, print_path},
    },
    colored::Colorize,
    random_color::{Luminosity, RandomColor},
};

#[cfg(feature = "logging-list")]
use std::collections::HashMap;
use std::fmt::Display;

#[cfg(feature = "logging-base")]
fn author_to_hex(author: AuthorID) -> String {
    format!("{:#x}", lsb_32(author))
}

#[cfg(feature = "logging-base")]
fn display_op_id<T: Clone + Hashable>(op: &Op<T>) -> String {
    let [r, g, b] = RandomColor::new()
        .luminosity(Luminosity::Light)
        .seed(lsb_32(op.author))
        .to_rgb_array();
    format!(
        "[{},{}]",
        author_to_hex(op.author).bold().truecolor(r, g, b),
        op.seq.to_string().yellow()
    )
}

#[cfg(feature = "logging-base")]
fn display_author(author: AuthorID) -> String {
    let [r, g, b] = RandomColor::new()
        .luminosity(Luminosity::Light)
        .seed(lsb_32(author))
        .to_rgb_array();
    format!(" {} ", author_to_hex(author))
        .black()
        .on_truecolor(r, g, b)
        .to_string()
}

pub trait DebugView {
    fn debug_view(&self, indent: usize) -> String;
}

impl<'a, T: CRDT<Inner = Value> + DebugView> BaseCRDT<'a, T> {
    pub fn debug_view(&self) {
        #[cfg(feature = "logging-json")]
        println!(
            "document is now:\n{}",
            self.doc.debug_view(0)
        );
    }

    pub fn log_try_apply(&self) {
        #[cfg(feature = "logging-json")]
        println!("{} applying operation", display_author(self.id),);
    }

    pub fn debug_digest_failure(&self, _op: SignedOp) {
        #[cfg(feature = "logging-json")]
        println!(
            "  {} cannot confirm signed_digest from {}",
            "digest failure!".red(),
            display_author(_op.author())
        );
    }

    pub fn log_missing_causal_dep(&self, _missing: &SignedDigest) {
        #[cfg(feature = "logging-json")]
        println!(
            "  {} haven't received op with digest {}",
            "missing causal dependency".red(),
            print_hex(_missing)
        );
    }

    pub fn log_finish_apply(&self, _op: &SignedOp) {
        #[cfg(feature = "logging-json")]
        println!(
            "  applying op to path: /{}",
            print_path(_op.inner.path.clone())
        );
    }
}

impl<T> Op<T>
where
    T: Hashable + Clone,
{
    pub fn debug_hash_failure(&self) {
        #[cfg(feature = "logging-base")]
        {
            println!("  {}", "hash failure!".red());
            println!("  expected: {}", print_hex(&self.id));
            println!("  computed: {}", print_hex(&self.hash_to_id()));
        }
    }
}

impl<T> DebugView for T
where
    T: Display,
{
    #[cfg(feature = "logging-base")]
    fn debug_view(&self, _indent: usize) -> String {
        self.to_string()
    }

    #[cfg(not(feature = "logging-base"))]
    fn debug_view(&self, _indent: usize) -> String {
        "".to_string()
    }
}

impl<T> DebugView for Op<T>
where
    T: DebugView + Hashable + Clone,
{
    #[cfg(not(feature = "logging-base"))]
    fn debug_view(&self, _indent: usize) -> String {
        "".to_string()
    }

    #[cfg(feature = "logging-json")]
    fn debug_view(&self, indent: usize) -> String {
        let op_id = display_op_id(self);
        let content = if self.id == ROOT_ID {
            "root".blue().bold().to_string()
        } else {
            self.content
                .as_ref()
                .map_or("[empty]".to_string(), |c| c.debug_view(indent + 2))
        };
        let content_str = if self.is_deleted && self.id != ROOT_ID {
            content.red().strikethrough().to_string()
        } else {
            content
        };

        format!("{op_id} {content_str}")
    }
}

impl<T> ListCRDT<T>
where
    T: Hashable + Clone,
{
    pub fn log_ops(&self, _highlight: Option<OpID>) {
        #[cfg(feature = "logging-list")]
        {
            let mut lines = Vec::<String>::new();

            // do in-order traversal
            let res: Vec<&Op<T>> = self.ops.iter().collect();
            if res.is_empty() {
                println!("[empty]");
            }

            // figure out parent-child hierarchies from origins
            let mut parent_child_map: HashMap<OpID, Vec<OpID>> = HashMap::new();
            for op in &res {
                let children = parent_child_map.entry(op.origin).or_default();
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
                let origin_idx = self.find_idx(op.origin).unwrap();
                let origin = &res[origin_idx];
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
                        .map_or("[empty]".to_string(), |c| c.hash())
                };
                if op.is_deleted && op.id != ROOT_ID {
                    lines.push(format!(
                        "{}{}{} {} {}",
                        prefixes,
                        cur_char,
                        display_op_id(op),
                        content.strikethrough().red(),
                        highlight_text
                    ));
                } else {
                    lines.push(format!(
                        "{}{}{} {} {}",
                        prefixes,
                        cur_char,
                        display_op_id(op),
                        content,
                        highlight_text
                    ));
                }
                prev = Some(op.id);
            }

            // full string
            let flat = self.iter().map(|t| t.hash()).collect::<Vec<_>>().join("");
            lines.push(format!("Flattened result: {}", flat));
            println!("{}", lines.join("\n"));
        }
    }

    pub fn log_apply(&self, _op: &Op<T>) {
        #[cfg(feature = "logging-list")]
        {
            if _op.is_deleted {
                println!(
                    "{} Performing a delete of {}@{}",
                    display_author(self.our_id),
                    display_op_id(op),
                    op.sequence_num(),
                );
                return;
            }

            println!(
                "{} Performing an insert of {}@{}: '{}' after {}",
                display_author(self.our_id),
                display_op_id(op),
                op.sequence_num(),
                op.content.as_ref().unwrap().hash(),
                display_op_id(op)
            );
        }
    }
}
