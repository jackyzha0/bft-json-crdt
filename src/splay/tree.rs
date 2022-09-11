use crate::splay::node::Node;
use core::cmp::Ordering;

use super::node::NodeComparable;

pub struct SplayTree<'a, T> {
    root: Option<&'a Node<'a, T>>,
}

impl<'a, T> Default for SplayTree<'a, T> {
    #[inline]
    fn default() -> SplayTree<'a, T> {
        SplayTree { root: None }
    }
}

impl<'a, T> SplayTree<'a, T> {
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    #[inline]
    pub fn root(&self) -> Option<&'a Node<'a, T>> {
        self.root
    }

    #[inline(never)]
    pub unsafe fn find(&mut self, key: &dyn NodeComparable<'a, T>) -> Option<&'a Node<'a, T>> {
        self.root.and_then(|root| {
            // splay the key to the top
            let root = self.splay(root, key);

            // if root is now the key we are looking for, it's present
            if key.compare_to_node(root) == Ordering::Equal {
                Some(root)
            } else {
                None
            }
        })
    }

    #[inline(never)]
    pub unsafe fn insert(
        &mut self,
        new_node: &'a Node<'a, T>,
    ) -> bool {
        match self.root {
            Some(root) => {
                // splay this key to the top
                let root = self.splay(root, new_node);
                // insert at root if we can
                // if we find the node already is there, return false
                match new_node.compare_to_node(root) {
                    Ordering::Equal => return false,
                    Ordering::Less => {
                        new_node.left.set(root.left.get());
                        new_node.right.set(Some(root));
                        root.left.set(None);
                    }
                    Ordering::Greater => {
                        new_node.right.set(root.right.get());
                        new_node.left.set(Some(root));
                        root.right.set(None);
                    }
                }
                // successful insert, update root
                self.root = Some(new_node);
                true
            }
            None => {
                // empty tree, insert at root
                self.root = Some(new_node);
                true
            }
        }
    }

    #[inline(never)]
    pub unsafe fn remove(&mut self, key: &dyn NodeComparable<'a, T>) -> Option<&'a Node<'a, T>> {
        self.root.and_then(|root| {
            let node_to_remove = self.splay(root, key);
            self.root = None;
            if key.compare_to_node(node_to_remove) == Ordering::Equal {
                // found the node, disconnect and clean up
                match node_to_remove.left.get() {
                    Some(node_left) => {
                        // make left node new root
                        let right = node_to_remove.right.get();
                        self.splay(node_left, key).right.set(right);
                    }
                    None => {
                        self.root = node_to_remove.right.get();
                    }
                }

                // disconnect old node
                node_to_remove.left.set(None);
                node_to_remove.right.set(None);
                return Some(node_to_remove);
            }

            // not in tree
            None
        })
    }

    pub fn traverse_collect(&self) -> Vec<&T> {
        let mut res = Vec::<&'a T>::new();
        if let Some(root) = self.root {
            root.traverse_collect(&mut res);
        }
        res
    }

    // O(log n) top-down splay
    // brings key to top if present
    unsafe fn splay(
        &mut self,
        mut current: &'a Node<'a, T>,
        key: &dyn NodeComparable<'a, T>,
    ) -> &'a Node<'a, T> {
        let null = Node::default();
        // last node of in-order traversal of left subtree
        // contains all items in the tree less than i
        let mut left = &null;
        // first node of in-order traversal of right subtree
        // contains all items in the tree greater than i
        let mut right = &null;

        // to do the splaying, we search down the root looking for key, two nodes at a time
        // we break links using link right and link left and add results to the right and left
        // subtrees respectively
        //
        // if we take two steps in the same direction (LL or RR) then we do a rotation before
        // breaking a link
        loop {
            match key.compare_to_node(current) {
                // key < current
                Ordering::Less => {
                    if let Some(mut current_left) = current.left.get() {
                        // if i < item(left(t))
                        if key.compare_to_node(current_left) == Ordering::Less {
                            // rotate right
                            current.left.set(current_left.right.get());
                            current_left.right.set(Some(current));
                            current = current_left;
                            match current.left.get() {
                                Some(l) => current_left = l,
                                None => break,
                            }
                        }
                        // link right
                        // break link between current and current.right
                        // set right to current
                        right.left.set(Some(current));
                        right = current;
                        current = current_left;
                    } else {
                        break;
                    }
                }

                // key > current
                Ordering::Greater => {
                    if let Some(mut current_right) = current.right.get() {
                        // if i > item(right(t))
                        if key.compare_to_node(current_right) == Ordering::Greater {
                            // rotate left
                            current.right.set(current_right.left.get());
                            current_right.left.set(Some(current));
                            current = current_right;
                            match current_right.right.get() {
                                Some(r) => current_right = r,
                                None => break,
                            }
                        }
                        // link left
                        left.right.set(Some(current));
                        left = current;
                        current = current_right;
                    } else {
                        break;
                    }
                }
                Ordering::Equal => break,
            }
        }

        // assemble
        left.right.set(current.left.get());
        right.left.set(current.right.get());
        current.left.set(null.right.get());
        current.right.set(null.left.get());
        self.root = Some(current);
        current
    }
}
