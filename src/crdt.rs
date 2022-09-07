use std::{cmp::Ordering};
use crate::linkedlist::{Ref, LinkedList};

type UUID = i64;
struct InsertOp<T> {
    id: UUID,
    origin: Ref<InsertOp<T>>, 
    is_deleted: bool,
    content: T,
    sequence_number: usize,
}

impl<T> InsertOp<T> {
    fn parent_ref(&self) -> &InsertOp<T> {
        unsafe { (*self.origin.as_ptr()).elem() }
    } 
}

impl<T> PartialEq for InsertOp<T> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl<T> Eq for InsertOp<T> {}

struct CRDT<T> {
    ops: LinkedList<InsertOp<T>>,
    highest_sequence_number: usize,
}

impl<T> CRDT<T> {
    fn new() -> Self {
        Self {
            ops: LinkedList::new(),
            highest_sequence_number: 0,
        }
    }

    fn insert(&mut self, new_op: InsertOp<T>) {
        // seek the cursor to where the parent is
        let mut insert_cursor = self.ops.cursor();
        insert_cursor.seek_forward_until(new_op.parent_ref());

        while let Some(cur_op) = insert_cursor.peek() {
            if new_op.sequence_number > cur_op.sequence_number {
                // new op is larger sequence number, safe to insert
                break;
            }

            // check our current insert's parent
            let mut cur_parent_cursor = self.ops.cursor();
            cur_parent_cursor.seek_forward_until(cur_op.parent_ref());

            // YATA rule 1: make sure that origin lines never cross
            let origin_line_crossing = cur_parent_cursor.index() < insert_cursor.index();
            // YATA rule 3: tie break by UUID, insertion with smaller id is on left
            let tie = cur_parent_cursor.index() == insert_cursor.index();
            let smaller_uuid = new_op.sequence_number == cur_op.sequence_number && new_op.id < cur_op.id;
            if origin_line_crossing || (tie && smaller_uuid) {
                break;
            }

            insert_cursor.seek_forward();
        }

        let mut c = self.ops.mut_cursor_from_ref_idx(insert_cursor.raw_ref(), insert_cursor.index());
        c.push_after(new_op);
    }
}

