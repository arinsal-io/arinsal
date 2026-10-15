//! Namespace word.
//!
//! A process carries one `AtomicU32`: the low 31 bits hold its namespace id (0 is root) and the
//! top bit marks a root service that tenant processes may reach.

/// Set on a process that processes of other namespaces may send to.
pub const NS_SHARED: u32 = 1 << 31;
/// Mask of the namespace id inside the namespace word.
pub const NS_ID_MASK: u32 = !NS_SHARED;

/// What delivery does with a signal that crosses namespaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NsGate {
    Allow,
    /// Drop silently, like a send to a dead pid.
    Drop,
    /// The sender sees `noproc`.
    NoProcess,
}
