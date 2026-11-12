// Port of erts/emulator/sys/common/erl_osenv.c, OTP-29.1.1.
//! The process-wide OS environment and the per-port merged environment.

use std::ffi::OsString;
use std::sync::{OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard};

type Index = usize;
const NIL: Index = Index::MAX;

struct Node {
    key: Vec<u8>,
    value: Vec<u8>,
    parent: Index,
    left: Index,
    right: Index,
    red: bool,
}

/// The Unix `erts_osenv_t`: raw byte keys in an intrusive red-black tree, with size counters.
pub(crate) struct ErlOsEnv {
    nodes: Vec<Option<Node>>,
    free: Vec<Index>,
    root: Index,
    variable_count: usize,
    content_size: usize,
}

impl ErlOsEnv {
    /// Port of `erts_osenv_init`.
    pub(crate) fn new() -> Self {
        Self {
            nodes: Vec::new(),
            free: Vec::new(),
            root: NIL,
            variable_count: 0,
            content_size: 0,
        }
    }

    fn node(&self, at: Index) -> &Node {
        self.nodes[at].as_ref().expect("live environment tree node")
    }

    fn node_mut(&mut self, at: Index) -> &mut Node {
        self.nodes[at].as_mut().expect("live environment tree node")
    }

    fn parent(&self, at: Index) -> Index {
        if at == NIL { NIL } else { self.node(at).parent }
    }

    fn left(&self, at: Index) -> Index {
        if at == NIL { NIL } else { self.node(at).left }
    }

    fn right(&self, at: Index) -> Index {
        if at == NIL { NIL } else { self.node(at).right }
    }

    fn red(&self, at: Index) -> bool {
        at != NIL && self.node(at).red
    }

    fn lookup(&self, key: &[u8]) -> Index {
        let mut at = self.root;
        while at != NIL {
            match key.cmp(self.node(at).key.as_slice()) {
                std::cmp::Ordering::Less => at = self.left(at),
                std::cmp::Ordering::Greater => at = self.right(at),
                std::cmp::Ordering::Equal => return at,
            }
        }
        NIL
    }

    /// Port of `erts_osenv_put_native`, including in-place tree replacement.
    pub(crate) fn put(&mut self, key: &[u8], value: &[u8]) {
        let existing = self.lookup(key);
        if existing != NIL {
            let old_len = self.node(existing).value.len();
            self.content_size -= self.node(existing).key.len() + old_len;
            self.node_mut(existing).value = value.to_vec();
            self.content_size += key.len() + value.len();
            return;
        }

        let index = self.free.pop().unwrap_or_else(|| {
            let index = self.nodes.len();
            self.nodes.push(None);
            index
        });
        let mut parent = NIL;
        let mut at = self.root;
        while at != NIL {
            parent = at;
            at = if key < self.node(at).key.as_slice() {
                self.left(at)
            } else {
                self.right(at)
            };
        }
        self.nodes[index] = Some(Node {
            key: key.to_vec(),
            value: value.to_vec(),
            parent,
            left: NIL,
            right: NIL,
            red: true,
        });
        if parent == NIL {
            self.root = index;
        } else if key < self.node(parent).key.as_slice() {
            self.node_mut(parent).left = index;
        } else {
            self.node_mut(parent).right = index;
        }
        self.insert_fixup(index);
        self.variable_count += 1;
        self.content_size += key.len() + value.len();
    }

    /// Port of `erts_osenv_unset_native`.
    pub(crate) fn unset(&mut self, key: &[u8]) -> bool {
        let old = self.lookup(key);
        if old == NIL {
            return false;
        }
        self.content_size -= self.node(old).key.len() + self.node(old).value.len();
        self.variable_count -= 1;
        self.delete(old);
        true
    }

    /// Port of `erts_osenv_get_native`.
    pub(crate) fn get(&self, key: &[u8]) -> Option<&[u8]> {
        let at = self.lookup(key);
        (at != NIL).then(|| self.node(at).value.as_slice())
    }

    /// Port of `erts_osenv_merge`; the source uses its ordinary tree walk.
    pub(crate) fn merge(&mut self, with: &Self, overwrite: bool) {
        for (key, value) in with.iter() {
            if overwrite || self.get(key).is_none() {
                self.put(key, value);
            }
        }
    }

    /// `env_rbt_foreach` order: the node is visited after its left and right subtrees.
    pub(crate) fn iter(&self) -> EnvIter<'_> {
        EnvIter {
            env: self,
            next: self.first_postorder(self.root),
        }
    }

    fn first_postorder(&self, mut at: Index) -> Index {
        if at == NIL {
            return NIL;
        }
        loop {
            if self.left(at) != NIL {
                at = self.left(at);
            } else if self.right(at) != NIL {
                at = self.right(at);
            } else {
                return at;
            }
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.variable_count
    }

    /// Storage reserved by `sys_drivers.c:add_spawn_env_block`.
    pub(crate) fn spawn_block_size(&self) -> usize {
        self.content_size + self.variable_count * 2
    }

    /// Port of `erts_osenv_clear`.
    #[allow(dead_code)]
    pub(crate) fn clear(&mut self) {
        self.nodes.clear();
        self.free.clear();
        self.root = NIL;
        self.variable_count = 0;
        self.content_size = 0;
    }

    fn rotate_left(&mut self, x: Index) {
        // Port of erts/emulator/beam/erl_rbtree.h (`left_rotate__`), OTP-29.1.1.
        let y = self.right(x);
        let beta = self.left(y);
        self.node_mut(x).right = beta;
        if beta != NIL {
            self.node_mut(beta).parent = x;
        }
        let parent = self.parent(x);
        self.node_mut(y).parent = parent;
        if parent == NIL {
            self.root = y;
        } else if x == self.left(parent) {
            self.node_mut(parent).left = y;
        } else {
            self.node_mut(parent).right = y;
        }
        self.node_mut(y).left = x;
        self.node_mut(x).parent = y;
    }

    fn rotate_right(&mut self, x: Index) {
        // Port of erts/emulator/beam/erl_rbtree.h (`right_rotate__`), OTP-29.1.1.
        let y = self.left(x);
        let beta = self.right(y);
        self.node_mut(x).left = beta;
        if beta != NIL {
            self.node_mut(beta).parent = x;
        }
        let parent = self.parent(x);
        self.node_mut(y).parent = parent;
        if parent == NIL {
            self.root = y;
        } else if x == self.right(parent) {
            self.node_mut(parent).right = y;
        } else {
            self.node_mut(parent).left = y;
        }
        self.node_mut(y).right = x;
        self.node_mut(x).parent = y;
    }

    fn insert_fixup(&mut self, mut z: Index) {
        // Port of erts/emulator/beam/erl_rbtree.h (`insert_fixup__`), OTP-29.1.1.
        while self.red(self.parent(z)) {
            let parent = self.parent(z);
            let grand = self.parent(parent);
            if parent == self.left(grand) {
                let uncle = self.right(grand);
                if self.red(uncle) {
                    self.node_mut(parent).red = false;
                    self.node_mut(uncle).red = false;
                    self.node_mut(grand).red = true;
                    z = grand;
                } else {
                    if z == self.right(parent) {
                        z = parent;
                        self.rotate_left(z);
                    }
                    let parent = self.parent(z);
                    let grand = self.parent(parent);
                    self.node_mut(parent).red = false;
                    self.node_mut(grand).red = true;
                    self.rotate_right(grand);
                }
            } else {
                let uncle = self.left(grand);
                if self.red(uncle) {
                    self.node_mut(parent).red = false;
                    self.node_mut(uncle).red = false;
                    self.node_mut(grand).red = true;
                    z = grand;
                } else {
                    if z == self.left(parent) {
                        z = parent;
                        self.rotate_right(z);
                    }
                    let parent = self.parent(z);
                    let grand = self.parent(parent);
                    self.node_mut(parent).red = false;
                    self.node_mut(grand).red = true;
                    self.rotate_left(grand);
                }
            }
        }
        if self.root != NIL {
            self.node_mut(self.root).red = false;
        }
    }

    fn transplant(&mut self, old: Index, new: Index) {
        let parent = self.parent(old);
        if parent == NIL {
            self.root = new;
        } else if old == self.left(parent) {
            self.node_mut(parent).left = new;
        } else {
            self.node_mut(parent).right = new;
        }
        if new != NIL {
            self.node_mut(new).parent = parent;
        }
    }

    fn minimum(&self, mut at: Index) -> Index {
        while self.left(at) != NIL {
            at = self.left(at);
        }
        at
    }

    fn delete(&mut self, z: Index) {
        // Port of erts/emulator/beam/erl_rbtree.h (`delete`), OTP-29.1.1.
        let mut y = z;
        let mut y_red = self.red(y);
        let x;
        let x_parent;
        if self.left(z) == NIL {
            x = self.right(z);
            x_parent = self.parent(z);
            self.transplant(z, x);
        } else if self.right(z) == NIL {
            x = self.left(z);
            x_parent = self.parent(z);
            self.transplant(z, x);
        } else {
            y = self.minimum(self.right(z));
            y_red = self.red(y);
            x = self.right(y);
            if self.parent(y) == z {
                x_parent = y;
                if x != NIL {
                    self.node_mut(x).parent = y;
                }
            } else {
                x_parent = self.parent(y);
                self.transplant(y, x);
                let z_right = self.right(z);
                self.node_mut(y).right = z_right;
                self.node_mut(z_right).parent = y;
            }
            self.transplant(z, y);
            let z_left = self.left(z);
            self.node_mut(y).left = z_left;
            self.node_mut(z_left).parent = y;
            self.node_mut(y).red = self.red(z);
        }
        if !y_red {
            self.delete_fixup(x, x_parent);
        }
        self.nodes[z] = None;
        self.free.push(z);
    }

    fn delete_fixup(&mut self, mut x: Index, mut parent: Index) {
        // Port of erts/emulator/beam/erl_rbtree.h (`delete_fixup__`), OTP-29.1.1.
        while x != self.root && !self.red(x) {
            if parent == NIL {
                break;
            }
            if x == self.left(parent) {
                let mut sibling = self.right(parent);
                if self.red(sibling) {
                    self.node_mut(sibling).red = false;
                    self.node_mut(parent).red = true;
                    self.rotate_left(parent);
                    sibling = self.right(parent);
                }
                if !self.red(self.left(sibling)) && !self.red(self.right(sibling)) {
                    if sibling != NIL {
                        self.node_mut(sibling).red = true;
                    }
                    x = parent;
                    parent = self.parent(x);
                } else {
                    if !self.red(self.right(sibling)) {
                        let left = self.left(sibling);
                        if left != NIL {
                            self.node_mut(left).red = false;
                        }
                        if sibling != NIL {
                            self.node_mut(sibling).red = true;
                            self.rotate_right(sibling);
                        }
                        sibling = self.right(parent);
                    }
                    if sibling != NIL {
                        self.node_mut(sibling).red = self.red(parent);
                    }
                    self.node_mut(parent).red = false;
                    let right = self.right(sibling);
                    if right != NIL {
                        self.node_mut(right).red = false;
                    }
                    self.rotate_left(parent);
                    x = self.root;
                    parent = NIL;
                }
            } else {
                let mut sibling = self.left(parent);
                if self.red(sibling) {
                    self.node_mut(sibling).red = false;
                    self.node_mut(parent).red = true;
                    self.rotate_right(parent);
                    sibling = self.left(parent);
                }
                if !self.red(self.right(sibling)) && !self.red(self.left(sibling)) {
                    if sibling != NIL {
                        self.node_mut(sibling).red = true;
                    }
                    x = parent;
                    parent = self.parent(x);
                } else {
                    if !self.red(self.left(sibling)) {
                        let right = self.right(sibling);
                        if right != NIL {
                            self.node_mut(right).red = false;
                        }
                        if sibling != NIL {
                            self.node_mut(sibling).red = true;
                            self.rotate_left(sibling);
                        }
                        sibling = self.left(parent);
                    }
                    if sibling != NIL {
                        self.node_mut(sibling).red = self.red(parent);
                    }
                    self.node_mut(parent).red = false;
                    let left = self.left(sibling);
                    if left != NIL {
                        self.node_mut(left).red = false;
                    }
                    self.rotate_right(parent);
                    x = self.root;
                    parent = NIL;
                }
            }
        }
        if x != NIL {
            self.node_mut(x).red = false;
        }
    }
}

pub(crate) struct EnvIter<'a> {
    env: &'a ErlOsEnv,
    next: Index,
}

impl<'a> Iterator for EnvIter<'a> {
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        // Port of `foreach_unordered__`: descend left then right and visit on ascent.
        let at = self.next;
        if at == NIL {
            return None;
        }
        let parent = self.env.parent(at);
        self.next = if parent == NIL {
            NIL
        } else if at == self.env.left(parent) && self.env.right(parent) != NIL {
            self.env.first_postorder(self.env.right(parent))
        } else {
            parent
        };
        let node = self.env.node(at);
        Some((node.key.as_slice(), node.value.as_slice()))
    }
}

static GLOBAL_ENV: OnceLock<RwLock<ErlOsEnv>> = OnceLock::new();

/// Port of `erts_sys_env_init` and `import_initial_env`: import the host environment once.
fn global() -> &'static RwLock<ErlOsEnv> {
    GLOBAL_ENV.get_or_init(|| {
        use std::os::unix::ffi::OsStrExt;
        let mut env = ErlOsEnv::new();
        for (key, value) in std::env::vars_os() {
            env.put(key.as_os_str().as_bytes(), value.as_os_str().as_bytes());
        }
        RwLock::new(env)
    })
}

/// Port of `erts_sys_rlock_global_osenv`.
pub(crate) fn read() -> RwLockReadGuard<'static, ErlOsEnv> {
    global().read().unwrap()
}

/// Port of `erts_sys_rwlock_global_osenv`.
pub(crate) fn write() -> RwLockWriteGuard<'static, ErlOsEnv> {
    global().write().unwrap()
}

/// Port of `erts_sys_explicit_8bit_getenv`, used by driver-facing VM code.
pub(crate) fn get(key: &[u8]) -> Option<Vec<u8>> {
    read().get(key).map(<[u8]>::to_vec)
}

/// Port of `erts_sys_explicit_8bit_putenv`, used by driver-facing VM code.
pub(crate) fn put(key: &[u8], value: &[u8]) {
    write().put(key, value);
}

/// Add boot-provided variables to the imported environment.
pub(crate) fn seed(vars: &[(String, String)]) {
    let mut env = write();
    for (key, value) in vars {
        env.put(key.as_bytes(), value.as_bytes());
    }
}

/// Merge the global tree with port options, in the same source-tree walk order as erts.
pub(crate) fn port_env(overrides: &[(Vec<u8>, Option<Vec<u8>>)]) -> ErlOsEnv {
    let global = read();
    let mut result = ErlOsEnv::new();
    result.merge(&global, false);
    drop(global);
    for (key, value) in overrides {
        match value {
            Some(value) => result.put(key, value),
            None => {
                result.unset(key);
            }
        }
    }
    result
}

/// Preserve native environment bytes as `OsString` for Rust process APIs.
pub(crate) fn os_string(bytes: &[u8]) -> OsString {
    use std::os::unix::ffi::OsStringExt;
    OsString::from_vec(bytes.to_vec())
}
