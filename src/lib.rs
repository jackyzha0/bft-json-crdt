use std::{marker::PhantomData, ptr::NonNull};

/// Heavily inspired by https://rust-unofficial.github.io/too-many-lists/sixth-basics.html
/// An unsafe doubly-linked list
pub struct LinkedList<T: Eq> {
    front: Ref<T>,
    back: Ref<T>,
    len: usize,

    // tell compiler we actually do store things of type `T`
    _phantom: PhantomData<T>,
}

struct Node<T> {
    next: Ref<T>,
    prev: Ref<T>,
    elem: T,
}

pub struct CursorMut<'a, T: Eq> {
    cur: Ref<T>,
    list: &'a mut LinkedList<T>,
    index: Option<usize>,
}

/// Optional non-null raw pointer to a Node<T>
type Ref<T> = Option<NonNull<Node<T>>>;

fn box_node<T>(node: Node<T>) -> NonNull<Node<T>> {
    unsafe { NonNull::new_unchecked(Box::into_raw(Box::new(node))) }
}

impl<T> LinkedList<T>
where
    T: Eq,
{
    pub fn new() -> Self {
        Self {
            front: None,
            back: None,
            len: 0,
            _phantom: PhantomData,
        }
    }

    pub fn pop_front(&mut self) -> Option<T> {
        // only do something if we actually have a head
        self.front.map(|head| {
            unsafe {
                // destruct the old node and put it into a box
                // warn: possible panic creating a boxed value from raw pointer
                let boxed_head = Box::from_raw(head.as_ptr());
                self.front = boxed_head.next;

                if let Some(new_head) = self.front {
                    // still have a head, delete old reference
                    // e.g. A -> B -> None
                    //      x -> B -> None
                    //         ^ clean this pointer up
                    (*new_head.as_ptr()).prev = None;
                } else {
                    // we are now an empty list, fully cleanup
                    self.back = None;
                }

                self.len -= 1;
                boxed_head.elem
            }
        })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn empty(&self) -> bool {
        self.len == 0
    }

    pub fn peek_front(&self) -> Option<&T> {
        unsafe { self.front.map(|head| &(*head.as_ptr()).elem) }
    }

    pub fn peek_back(&self) -> Option<&T> {
        unsafe { self.back.map(|head| &(*head.as_ptr()).elem) }
    }

    pub fn cursor_mut(&mut self) -> CursorMut<T> {
        CursorMut {
            list: self,
            cur: None,
            index: None,
        }
    }
}

impl<'a, T> CursorMut<'a, T>
where
    T: Eq,
{
    pub fn index(&self) -> Option<usize> {
        self.index
    }

    pub fn at_end(&self) -> bool {
        self.index == None
    }

    /// Seek the cursor forward a single step, jumping to start if we are at the ghost element
    pub fn seek_forward(&mut self) {
        if let Some(cur) = self.cur {
            unsafe {
                // move to next ref
                self.cur = (*cur.as_ptr()).next;
                if self.cur.is_some() {
                    // increment index
                    self.index = Some(self.index.unwrap() + 1);
                } else {
                    // we've hit the ghost, null the index
                    self.index = None;
                }
            }
        } else if !self.list.empty() {
            // on ghost element, move to start
            self.cur = self.list.front;
            self.index = Some(0);
        }
    }

    /// Seek the cursor back a single step, jumping to end if we are at the ghost element
    pub fn seek_backward(&mut self) {
        if let Some(cur) = self.cur {
            unsafe {
                self.cur = (*cur.as_ptr()).prev;
                if self.cur.is_some() {
                    self.index = Some(self.index.unwrap() - 1);
                } else {
                    self.index = None;
                }
            }
        } else if !self.list.empty() {
            self.cur = self.list.back;
            self.index = Some(self.list.len - 1);
        }
    }

    pub fn seek_forward_until(&mut self, elem: T) {
        while let Some(cur_el) = self.peek() {
            if *cur_el == elem {
                return;
            }
            self.seek_forward();
        }
    }

    pub fn seek_backward_until(&mut self, elem: T) {
        while let Some(cur_el) = self.peek() {
            if *cur_el == elem {
                return;
            }
            self.seek_backward();
        }
    }

    pub fn peek(&mut self) -> Option<&T> {
        unsafe { self.cur.map(|node| &(*node.as_ptr()).elem) }
    }

    pub fn current(&mut self) -> Option<&mut T> {
        unsafe { self.cur.map(|node| &mut (*node.as_ptr()).elem) }
    }

    pub fn push_after(&mut self, elem: T) {
        let new_node = Node {
            prev: None,
            next: None,
            elem,
        };
        let new_node_ptr = box_node(new_node);
        unsafe {
            if let Some(cur_ptr) = self.cur {
                if let Some(next_ptr) = (*cur_ptr.as_ptr()).next {
                    // well-defined current and next e.g.
                    // start -> A <-> B <-> C <- end
                    //                ^ cursor
                    // .insert_after(D)
                    // start -> A <-> B <-> D <-> C <- end
                    //                ^ cursor
                    debug_assert!(self.list.len() >= 2);
                    (*cur_ptr.as_ptr()).next = Some(new_node_ptr);
                    (*new_node_ptr.as_ptr()).prev = Some(cur_ptr);
                    (*new_node_ptr.as_ptr()).next = Some(next_ptr);
                    (*next_ptr.as_ptr()).prev = Some(new_node_ptr);
                } else {
                    // well-defined current but no next e.g.
                    // start -> A <-> B <- end
                    //                ^ cursor
                    // .insert_after(D)
                    // start -> A <-> B <-> D <- end
                    //                ^ cursor
                    debug_assert!(self.list.len() == 1);
                    (*cur_ptr.as_ptr()).next = Some(new_node_ptr);
                    (*new_node_ptr.as_ptr()).prev = Some(cur_ptr);
                    self.list.back = Some(new_node_ptr);
                }
            } else {
                if let Some(head_ptr) = self.list.front {
                    // ghost cursor but has head e.g.
                    // start -> A <-> B <- end
                    //   ^ cursor
                    // .insert_after(D)
                    // start -> D <-> A <-> B <- end
                    //   ^ cursor
                    debug_assert!(self.list.len() >= 1);
                    (*new_node_ptr.as_ptr()).next = Some(head_ptr);
                    (*head_ptr.as_ptr()).prev = Some(new_node_ptr);
                    self.list.front = Some(new_node_ptr);
                } else {
                    // ghost cursor empty list e.g.
                    // start ->  <- end
                    //   ^ cursor
                    debug_assert!(self.list.len() == 0);
                    self.list.front = Some(new_node_ptr);
                    self.list.back = Some(new_node_ptr);
                }
                
            }
        }
        self.list.len += 1;
    }
}

impl<T> Drop for LinkedList<T>
where
    T: Eq,
{
    fn drop(&mut self) {
        while self.len() > 0 {
            self.pop_front();
        }
    }
}

#[cfg(test)]
mod test {
    use super::LinkedList;

    #[test]
    fn test_front_empty() {
        let mut list = LinkedList::<i32>::new();
        assert_eq!(list.len(), 0);
        assert_eq!(list.pop_front(), None);
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn test_front_one_item() {
        let mut list = LinkedList::<i32>::new();
        let mut c = list.cursor_mut();
        c.push_after(1);
        assert_eq!(list.len(), 1);
        assert_eq!(list.pop_front(), Some(1));
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn test_front_interleaved() {
        let mut list = LinkedList::<i32>::new();
        let mut c = list.cursor_mut();
        c.push_after(1);
        c.push_after(2);
        c.push_after(3);
        assert_eq!(list.len(), 3);
        assert_eq!(list.pop_front(), Some(3));
        assert_eq!(list.pop_front(), Some(2));
        assert_eq!(list.len(), 1);
        let mut c = list.cursor_mut();
        c.push_after(4);
        assert_eq!(list.pop_front(), Some(4));
        assert_eq!(list.pop_front(), Some(1));
        assert_eq!(list.pop_front(), None);
        assert_eq!(list.len(), 0);
    }
}
