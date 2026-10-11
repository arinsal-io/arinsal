//! Red-black tree used by `erlang:'--'/2`.

use arinsal_term::{Term, cmp_exact, global_atoms};
use std::cmp::Ordering;

const NONE: usize = usize::MAX;

/// One node in the preallocated contiguous multiset node area.
///
/// Port of `erts/emulator/beam/erl_bif_lists.c:389-398` and the configured
/// `erl_rbtree.h` node operations, OTP-29.1.1. Integer links retain the C
/// pointer slots' order and width while keeping all tree manipulation safe.
#[repr(C)]
#[derive(Clone, Copy)]
struct Node {
    parent: usize,
    left: usize,
    right: usize,
    is_red: i32,
    key: Term,
    count: usize,
}

impl Node {
    fn new(key: Term, parent: usize, is_red: bool) -> Self {
        Self {
            parent,
            left: NONE,
            right: NONE,
            is_red: i32::from(is_red),
            key,
            count: 1,
        }
    }
}

/// A contiguous red-black multiset with one count per exact Erlang key.
pub(super) struct RbTree {
    nodes: Vec<Node>,
    root: usize,
}

impl RbTree {
    /// Reserve room for the maximum number of distinct input keys.
    ///
    /// Port of `subtract_enter_set_build` at `erl_bif_lists.c:797-804`, OTP-29.1.1.
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            nodes: Vec::with_capacity(capacity),
            root: NONE,
        }
    }

    /// Add one occurrence, returning the existing or newly inserted node.
    ///
    /// Port of `erl_rbtree.h:1056-1139` (`insert_aux__` and
    /// `lookup_insert`), OTP-29.1.1.
    pub(super) fn insert(&mut self, key: Term) -> usize {
        let mut parent = NONE;
        let mut cursor = self.root;
        let mut direction = Ordering::Equal;
        while cursor != NONE {
            parent = cursor;
            direction = subtract_term_cmp(key, self.nodes[cursor].key);
            if direction == Ordering::Equal {
                self.nodes[cursor].count += 1;
                return cursor;
            }
            cursor = if direction == Ordering::Less {
                self.nodes[cursor].left
            } else {
                self.nodes[cursor].right
            };
        }

        let index = self.nodes.len();
        self.nodes.push(Node::new(key, parent, parent != NONE));
        if parent == NONE {
            self.root = index;
            self.nodes[index].is_red = 0;
        } else if direction == Ordering::Less {
            self.nodes[parent].left = index;
        } else {
            self.nodes[parent].right = index;
        }

        if parent != NONE && self.is_red(parent) {
            self.insert_fixup(index);
        }
        index
    }

    /// Find a key by OTP's exact term ordering.
    ///
    /// Port of `erl_rbtree.h:1249-1292` (`lookup`), OTP-29.1.1.
    pub(super) fn lookup(&self, key: Term) -> Option<usize> {
        let mut cursor = self.root;
        while cursor != NONE {
            match subtract_term_cmp(key, self.nodes[cursor].key) {
                Ordering::Equal => return Some(cursor),
                Ordering::Less => cursor = self.nodes[cursor].left,
                Ordering::Greater => cursor = self.nodes[cursor].right,
            }
        }
        None
    }

    /// Return the number of still available occurrences for a found key.
    #[cfg(test)]
    pub(super) fn count(&self, node: usize) -> usize {
        self.nodes[node].count
    }

    /// Consume one occurrence of a key, deleting its node when its count ends.
    ///
    /// Port of `erl_rbtree.h:705-935` (`delete`), OTP-29.1.1.
    pub(super) fn consume(&mut self, node: usize) {
        if self.nodes[node].count > 1 {
            self.nodes[node].count -= 1;
            return;
        }
        self.delete_node(node);
    }

    fn is_red(&self, node: usize) -> bool {
        node != NONE && self.nodes[node].is_red != 0
    }

    fn set_red(&mut self, node: usize) {
        if node != NONE {
            self.nodes[node].is_red = 1;
        }
    }

    fn set_black(&mut self, node: usize) {
        if node != NONE {
            self.nodes[node].is_red = 0;
        }
    }

    fn parent(&self, node: usize) -> usize {
        if node == NONE {
            NONE
        } else {
            self.nodes[node].parent
        }
    }

    fn left(&self, node: usize) -> usize {
        if node == NONE {
            NONE
        } else {
            self.nodes[node].left
        }
    }

    fn right(&self, node: usize) -> usize {
        if node == NONE {
            NONE
        } else {
            self.nodes[node].right
        }
    }

    /// Rotate a subtree left.
    ///
    /// Port of `erl_rbtree.h:565-600` (`left_rotate__`), OTP-29.1.1.
    fn left_rotate(&mut self, x: usize) {
        let y = self.nodes[x].right;
        let left = self.nodes[y].left;
        self.nodes[x].right = left;
        if left != NONE {
            self.nodes[left].parent = x;
        }
        let parent = self.nodes[x].parent;
        self.nodes[y].parent = parent;
        if parent == NONE {
            self.root = y;
        } else if self.nodes[parent].left == x {
            self.nodes[parent].left = y;
        } else {
            self.nodes[parent].right = y;
        }
        self.nodes[y].left = x;
        self.nodes[x].parent = y;
    }

    /// Rotate a subtree right.
    ///
    /// Port of `erl_rbtree.h:602-639` (`right_rotate__`), OTP-29.1.1.
    fn right_rotate(&mut self, x: usize) {
        let y = self.nodes[x].left;
        let right = self.nodes[y].right;
        self.nodes[x].left = right;
        if right != NONE {
            self.nodes[right].parent = x;
        }
        let parent = self.nodes[x].parent;
        self.nodes[y].parent = parent;
        if parent == NONE {
            self.root = y;
        } else if self.nodes[parent].right == x {
            self.nodes[parent].right = y;
        } else {
            self.nodes[parent].left = y;
        }
        self.nodes[y].right = x;
        self.nodes[x].parent = y;
    }

    /// Restore the red-black properties after insertion.
    ///
    /// Port of `erl_rbtree.h:939-1054` (`insert_fixup__`), OTP-29.1.1.
    fn insert_fixup(&mut self, mut x: usize) {
        while x != self.root && self.is_red(self.parent(x)) {
            let parent = self.parent(x);
            let grandparent = self.parent(parent);
            if parent == self.nodes[grandparent].left {
                let uncle = self.nodes[grandparent].right;
                if self.is_red(uncle) {
                    self.set_black(uncle);
                    self.set_black(parent);
                    self.set_red(grandparent);
                    x = grandparent;
                } else {
                    if x == self.nodes[parent].right {
                        x = parent;
                        self.left_rotate(x);
                    }
                    let parent = self.parent(x);
                    let grandparent = self.parent(parent);
                    self.set_black(parent);
                    self.set_red(grandparent);
                    self.right_rotate(grandparent);
                    break;
                }
            } else {
                let uncle = self.nodes[grandparent].left;
                if self.is_red(uncle) {
                    self.set_black(uncle);
                    self.set_black(parent);
                    self.set_red(grandparent);
                    x = grandparent;
                } else {
                    if x == self.nodes[parent].left {
                        x = parent;
                        self.right_rotate(x);
                    }
                    let parent = self.parent(x);
                    let grandparent = self.parent(parent);
                    self.set_black(parent);
                    self.set_red(grandparent);
                    self.left_rotate(grandparent);
                    break;
                }
            }
        }
        self.set_black(self.root);
    }

    /// Replace one node with another, retaining the removed node's position.
    ///
    /// Port of `erl_rbtree.h:642-688` (`replace__`), OTP-29.1.1.
    fn replace(&mut self, old: usize, new: usize) {
        let parent = self.nodes[old].parent;
        let left = self.nodes[old].left;
        let right = self.nodes[old].right;
        if parent == NONE {
            self.root = new;
        } else if self.nodes[parent].left == old {
            self.nodes[parent].left = new;
        } else {
            self.nodes[parent].right = new;
        }
        if left != NONE {
            self.nodes[left].parent = new;
        }
        if right != NONE {
            self.nodes[right].parent = new;
        }
        self.nodes[new].is_red = self.nodes[old].is_red;
        self.nodes[new].parent = parent;
        self.nodes[new].left = left;
        self.nodes[new].right = right;
    }

    /// Remove a node and restore the red-black properties.
    ///
    /// Port of `erl_rbtree.h:705-935` (`delete`), OTP-29.1.1.
    fn delete_node(&mut self, z: usize) {
        let mut y = z;
        if self.nodes[z].left != NONE && self.nodes[z].right != NONE {
            y = self.nodes[z].right;
            while self.nodes[y].left != NONE {
                y = self.nodes[y].left;
            }
        }

        let left = self.nodes[y].left;
        let x = if left != NONE {
            left
        } else {
            self.nodes[y].right
        };
        let spliced_is_black = !self.is_red(y);
        let mut parent = self.nodes[y].parent;
        if x != NONE {
            self.nodes[x].parent = parent;
        }
        if parent == NONE {
            self.root = x;
        } else if self.nodes[parent].left == y {
            self.nodes[parent].left = x;
        } else {
            self.nodes[parent].right = x;
        }

        if y != z {
            self.replace(z, y);
            if x == NONE && parent == z {
                parent = y;
            }
        }

        if spliced_is_black {
            let mut x = x;
            while !self.is_red(x) && x != self.root && parent != NONE {
                if x == self.nodes[parent].left {
                    let mut sibling = self.nodes[parent].right;
                    if self.is_red(sibling) {
                        self.set_black(sibling);
                        self.set_red(parent);
                        self.left_rotate(parent);
                        if x != NONE {
                            parent = self.parent(x);
                        }
                        sibling = self.nodes[parent].right;
                    }
                    let left = self.left(sibling);
                    let right = self.right(sibling);
                    if !self.is_red(left) && !self.is_red(right) {
                        self.set_red(sibling);
                        x = parent;
                        parent = self.parent(x);
                    } else {
                        if !self.is_red(right) {
                            self.set_black(left);
                            self.set_red(sibling);
                            self.right_rotate(sibling);
                            if x != NONE {
                                parent = self.parent(x);
                            }
                            sibling = self.nodes[parent].right;
                        }
                        if self.is_red(parent) {
                            self.set_black(parent);
                            self.set_red(sibling);
                        }
                        self.set_black(self.right(sibling));
                        self.left_rotate(parent);
                        x = self.root;
                        parent = NONE;
                    }
                } else {
                    let mut sibling = self.nodes[parent].left;
                    if self.is_red(sibling) {
                        self.set_black(sibling);
                        self.set_red(parent);
                        self.right_rotate(parent);
                        if x != NONE {
                            parent = self.parent(x);
                        }
                        sibling = self.nodes[parent].left;
                    }
                    let left = self.left(sibling);
                    let right = self.right(sibling);
                    if !self.is_red(right) && !self.is_red(left) {
                        self.set_red(sibling);
                        x = parent;
                        parent = self.parent(x);
                    } else {
                        if !self.is_red(left) {
                            self.set_black(right);
                            self.set_red(sibling);
                            self.left_rotate(sibling);
                            if x != NONE {
                                parent = self.parent(x);
                            }
                            sibling = self.nodes[parent].left;
                        }
                        if self.is_red(parent) {
                            self.set_black(parent);
                            self.set_red(sibling);
                        }
                        self.set_black(self.left(sibling));
                        self.right_rotate(parent);
                        x = self.root;
                        parent = NONE;
                    }
                }
            }
            self.set_black(x);
        }
    }
}

/// Compare tagged terms using `erts_cmp`'s immediate fast paths before falling
/// back to the full exact term order.
///
/// Port of `erts/emulator/beam/utils.c:1723-1737` (`erts_cmp` immediate cases),
/// reached through `erl_utils.h:122` (`CMP_TERM`), OTP-29.1.1.
#[inline]
fn subtract_term_cmp(a: Term, b: Term) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    if let (Some(a), Some(b)) = (a.as_small(), b.as_small()) {
        return a.cmp(&b);
    }
    if let (Some(a), Some(b)) = (a.as_atom(), b.as_atom()) {
        let atoms = global_atoms();
        return atoms.text(a).cmp(&atoms.text(b));
    }
    cmp_exact(a, b)
}

#[cfg(test)]
mod tests {
    use super::{NONE, Node, RbTree};
    use arinsal_term::{Term, cmp_exact};
    use std::cmp::Ordering;

    #[test]
    fn node_layout_matches_erts_subtract_tree() {
        assert_eq!(std::mem::size_of::<Node>(), 48);
        assert_eq!(std::mem::offset_of!(Node, parent), 0);
        assert_eq!(std::mem::offset_of!(Node, left), 8);
        assert_eq!(std::mem::offset_of!(Node, right), 16);
        assert_eq!(std::mem::offset_of!(Node, is_red), 24);
        assert_eq!(std::mem::offset_of!(Node, key), 32);
        assert_eq!(std::mem::offset_of!(Node, count), 40);
    }

    fn assert_valid(tree: &RbTree) {
        fn walk(tree: &RbTree, node: usize, parent: usize) -> (usize, usize) {
            if node == NONE {
                return (1, 0);
            }
            let current = tree.nodes[node];
            assert_eq!(current.parent, parent);
            if current.is_red != 0 {
                assert!(!tree.is_red(current.left));
                assert!(!tree.is_red(current.right));
            }
            if current.left != NONE {
                assert_eq!(
                    cmp_exact(tree.nodes[current.left].key, current.key),
                    Ordering::Less
                );
            }
            if current.right != NONE {
                assert_eq!(
                    cmp_exact(tree.nodes[current.right].key, current.key),
                    Ordering::Greater
                );
            }
            let (left_black, left_nodes) = walk(tree, current.left, node);
            let (right_black, right_nodes) = walk(tree, current.right, node);
            assert_eq!(left_black, right_black);
            (
                left_black + usize::from(current.is_red == 0),
                left_nodes + right_nodes + 1,
            )
        }

        if tree.root != NONE {
            assert!(!tree.is_red(tree.root));
        }
        let (_, visited) = walk(tree, tree.root, NONE);
        assert!(visited <= tree.nodes.len());
    }

    #[test]
    fn insertion_and_deletion_preserve_tree_and_multiset_counts() {
        let repeated = Term::small(17).unwrap();
        let mut multiset = RbTree::with_capacity(3);
        let first = multiset.insert(repeated);
        assert_eq!(multiset.insert(repeated), first);
        assert_eq!(multiset.insert(repeated), first);
        assert_eq!(multiset.nodes.len(), 1);
        assert_eq!(multiset.count(first), 3);
        multiset.consume(first);
        assert_eq!(multiset.count(first), 2);
        multiset.consume(first);
        assert_eq!(multiset.count(first), 1);
        multiset.consume(first);
        assert_eq!(multiset.root, NONE);

        let mut tree = RbTree::with_capacity(256);
        let mut values = Vec::new();
        for step in 0..256 {
            let key = Term::small(((step * 73) % 257) as i64).unwrap();
            values.push(key);
            tree.insert(key);
            assert_valid(&tree);
        }
        for key in values {
            let node = tree.lookup(key).unwrap();
            assert!(tree.count(node) > 0);
            tree.consume(node);
            assert_valid(&tree);
        }
        assert_eq!(tree.root, NONE);
    }
}
