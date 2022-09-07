use std::{marker::PhantomData, ptr::NonNull, borrow::BorrowMut};

/// Heavily inspired by https://rust-unofficial.github.io/too-many-lists/sixth-basics.html
/// An unsafe doubly-linked list
pub struct LinkedList<T: Eq> {
    front: Option<Ref<T>>,
    back: Option<Ref<T>>,
    len: usize,

    // tell compiler we actually do store things of type `T`
    _phantom: PhantomData<T>,
}

pub struct Node<T> {
    next: Option<Ref<T>>,
    prev: Option<Ref<T>>,
    elem: T,
}

impl<T> Node<T> {
    pub fn elem(&self) -> &T {
        &self.elem
    }
}

pub struct CursorMut<'a, T: Eq> {
    cur: Option<Ref<T>>,
    list: &'a mut LinkedList<T>,
    index: Option<usize>,
}

pub struct Cursor<'a, T: Eq> {
    cur: Option<Ref<T>>,
    list: &'a LinkedList<T>,
    index: Option<usize>,
}

/// Non-null raw pointer to a Node<T>
pub type Ref<T> = NonNull<Node<T>>;
fn box_node<T>(node: Node<T>) -> Ref<T> { 
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
    
    pub fn cursor(&self) -> Cursor<T> {
        Cursor {
            list: self,
            cur: None,
            index: None,
        }
    }

    pub fn mut_cursor_from_ref_idx(&mut self, cur: Option<Ref<T>>, index: Option<usize>) -> CursorMut<T> {
        CursorMut { cur, list: self, index }
    }

    pub fn pop_front(&mut self) -> Option<T> {
        self.cursor_mut().pop_after()
    }

    pub fn push_front(&mut self, elem: T) {
        self.cursor_mut().push_after(elem)
    }

    pub fn into_iter(self) -> IntoIter<T> {
        IntoIter(self)
    }
}

impl<'a, T> Cursor<'a, T> where T: Eq {
    pub fn raw_ref(&self) -> Option<Ref<T>> {
        self.cur
    }

    pub fn index(&self) -> Option<usize> {
        self.index
    }

    pub fn at_end(&self) -> bool {
        self.index == None
    }

    pub fn seek_front(&mut self) {
        self.cur = None;
        self.index = None;
    }
    
    pub fn seek_back(&mut self) {
        self.cur = self.list.back;
        self.index = self.cur.map(|_| self.list.len - 1);
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

    pub fn seek_forward_until(&mut self, elem: &T) {
        if self.cur.is_none() {
            self.seek_forward();
        }
        while let Some(cur_el) = self.peek() {
            if cur_el == elem {
                return;
            }
            self.seek_forward();
        }
    }

    pub fn seek_backward_until(&mut self, elem: &T) {
        if self.cur.is_none() {
            self.seek_backward();
        }
        while let Some(cur_el) = self.peek() {
            if cur_el == elem {
                return;
            }
            self.seek_backward();
        }
    }

    pub fn peek(&self) -> Option<&T> {
        unsafe { self.cur.map(|node| &(*node.as_ptr()).elem) }
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

    pub fn seek_front(&mut self) {
        self.cur = None;
        self.index = None;
    }
    
    pub fn seek_back(&mut self) {
        self.cur = self.list.back;
        self.index = self.cur.map(|_| self.list.len - 1);
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

    pub fn seek_forward_until(&mut self, elem: &T) {
        if self.cur.is_none() {
            self.seek_forward();
        }
        while let Some(cur_el) = self.peek() {
            if cur_el == elem {
                return;
            }
            self.seek_forward();
        }
    }

    pub fn seek_backward_until(&mut self, elem: &T) {
        if self.cur.is_none() {
            self.seek_backward();
        }
        while let Some(cur_el) = self.peek() {
            if cur_el == elem {
                return;
            }
            self.seek_backward();
        }
    }

    pub fn peek(&self) -> Option<&T> {
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
                    //                   ^ cursor
                    // .insert_after(D)
                    // start -> A <-> B <-> D <-> C <- end
                    //                   ^ cursor
                    (*cur_ptr.as_ptr()).next = Some(new_node_ptr);
                    (*new_node_ptr.as_ptr()).prev = Some(cur_ptr);
                    (*new_node_ptr.as_ptr()).next = Some(next_ptr);
                    (*next_ptr.as_ptr()).prev = Some(new_node_ptr);
                } else {
                    // well-defined current but no next e.g.
                    // start -> A <-> B <- end
                    //                  ^ cursor
                    // .insert_after(D)
                    // start -> A <-> B <-> D <- end
                    //                  ^ cursor
                    (*cur_ptr.as_ptr()).next = Some(new_node_ptr);
                    (*new_node_ptr.as_ptr()).prev = Some(cur_ptr);
                    self.list.back = Some(new_node_ptr);
                }
            } else {
                if let Some(head_ptr) = self.list.front {
                    // ghost cursor but has head e.g.
                    // start -> A <-> B <- end
                    //        ^ cursor
                    // .insert_after(D)
                    // start -> D <-> A <-> B <- end
                    //        ^ cursor
                    (*new_node_ptr.as_ptr()).next = Some(head_ptr);
                    (*head_ptr.as_ptr()).prev = Some(new_node_ptr);
                    self.list.front = Some(new_node_ptr);
                } else {
                    // ghost cursor empty list e.g.
                    // start ->  <- end
                    //        ^ cursor
                    self.list.front = Some(new_node_ptr);
                    self.list.back = Some(new_node_ptr);
                }
            }
        }
        self.list.len += 1;
    }

    pub fn pop_after(&mut self) -> Option<T> {
        unsafe {
            if let Some(cur_ptr) = self.cur {
                if let Some(next_ptr) = (*cur_ptr.as_ptr()).next {
                    if let Some(next_next_ptr) = (*next_ptr.as_ptr()).next {
                        // well-defined current, next and next-next e.g.
                        // start -> A <-> B <-> C <-> D <- end
                        //                   ^ cursor
                        // .pop_after()
                        // start -> A <-> B <-> D <- end
                        //                  ^ cursor
                        let boxed_node = Box::from_raw(next_ptr.as_ptr());
                        (*cur_ptr.as_ptr()).next = Some(next_next_ptr);
                        (*next_next_ptr.as_ptr()).prev = Some(cur_ptr);
                        self.list.len -= 1;
                        Some(boxed_node.elem)
                    } else {
                        // well-defined current and next e.g.
                        // start -> A <-> B <-> C <- end
                        //                   ^ cursor
                        // .pop_after()
                        // start -> A <-> B <- end
                        //                  ^ cursor
                        // need to set new back
                        let boxed_node = Box::from_raw(next_ptr.as_ptr());
                        (*cur_ptr.as_ptr()).next = None;
                        self.list.back = Some(cur_ptr);
                        self.list.len -= 1;
                        Some(boxed_node.elem)
                    }
                } else {
                    // well-defined current but no next e.g.
                    // start -> A <-> B <- end
                    //                   ^ cursor
                    // .pop_after()
                    // start -> A <-> B <- end
                    //                   ^ cursor
                    None
                }
            } else {
                if let Some(head_ptr) = self.list.front {
                    if let Some(head_next_ptr) = (*head_ptr.as_ptr()).next {
                        // ghost cursor but has head and hext.next e.g.
                        // start -> A <-> B <- end
                        //        ^ cursor
                        // .pop_after()
                        // start -> B <- end
                        //        ^ cursor
                        // set new front
                        let boxed_node = Box::from_raw(head_ptr.as_ptr());
                        (*head_next_ptr.as_ptr()).prev = None;
                        self.list.front = Some(head_next_ptr);
                        self.list.len -= 1;
                        Some(boxed_node.elem)
                    } else {
                        // ghost cursor but has head and hext.next e.g.
                        // start -> A <- end
                        //        ^ cursor
                        // .pop_after()
                        // start -> <- end
                        //        ^ cursor
                        // remove front and back
                        let boxed_node = Box::from_raw(head_ptr.as_ptr());
                        self.list.front = None;
                        self.list.back = None;
                        self.list.len -= 1;
                        Some(boxed_node.elem)
                    }
                } else {
                    // ghost cursor empty list e.g.
                    // start ->  <- end
                    //        ^ cursor
                    None
                }
            }
        }
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

pub struct IntoIter<T>(LinkedList<T>) where T: Eq;
impl<T> Iterator for IntoIter<T> where T: Eq {
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.pop_front()
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
        assert_eq!(list.peek_front(), None);
        assert_eq!(list.peek_back(), None);
    }

    #[test]
    fn test_cursor_seek_and_push_forward() {
        let mut list = LinkedList::<i32>::new();
        let mut c = list.cursor_mut();
        // |1
        c.push_after(1);

        // |5,1
        c.push_after(5);

        // 5|1
        c.seek_forward();

        // 5|3,1
        c.push_after(3);

        // 5|4,3,1
        c.push_after(4);

        // 5,4,3|1
        c.seek_forward();
        c.seek_forward();

        // 5,4,3|2,1
        c.push_after(2);

        // 5,4,3,2,1|0
        c.seek_forward();
        c.seek_forward();
        c.push_after(0);

        assert_eq!(list.peek_front(), Some(&5));
        assert_eq!(list.peek_back(), Some(&0));
        assert!(list.into_iter().eq(vec![5,4,3,2,1,0]));
    }

    #[test]
    fn test_cursor_complex() {
        let mut list = LinkedList::<i32>::new();
        let mut c = list.cursor_mut();

        // |1
        c.seek_backward();
        c.seek_backward();
        c.push_after(1);

        // |
        assert_eq!(c.pop_after(), Some(1));

        // |1,2,3
        c.push_after(3);
        c.push_after(2);
        c.push_after(1);

        // 1,2,3|4
        c.seek_forward_until(&3);
        assert_eq!(c.peek(), Some(&3));
        c.push_after(4);

        // 1|2,3,4
        c.seek_backward_until(&1);
        assert_eq!(c.peek(), Some(&1));
        c.seek_front();
        c.push_after(0);
        assert_eq!(list.peek_front(), Some(&0));
        assert_eq!(list.peek_back(), Some(&4));
        assert!(list.into_iter().eq(vec![0,1,2,3,4]));    
    }
}
