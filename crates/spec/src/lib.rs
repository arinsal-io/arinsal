//! OTP 29.1.1 generic opcode and BIF tables, generated from the bundled specs.

#![forbid(unsafe_code)]

/// Loader handling class of a BIF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BifKind {
    /// Ordinary BIF.
    Bif,
    /// Operator or guard BIF.
    Ubif,
    /// BIF requiring garbage collection or the caller's location; invoked through an export entry.
    Hbif,
}

/// One declaration from OTP's `bif.tab`.
#[derive(Clone, Copy, Debug)]
pub struct BifSpec {
    /// Zero-based position in `bif.tab`.
    pub index: u16,
    /// Loader handling class.
    pub kind: BifKind,
    /// Defining module.
    pub module: &'static str,
    /// Unquoted function atom.
    pub name: &'static str,
    /// Function arity.
    pub arity: u8,
    /// Optional C entry point.
    pub c_name: Option<&'static str>,
}

include!(concat!(env!("OUT_DIR"), "/tables.rs"));

/// Find a BIF by MFA using a sorted index built once.
pub fn bif_lookup(module: &str, name: &str, arity: u8) -> Option<&'static BifSpec> {
    use std::sync::OnceLock;
    static SORTED: OnceLock<Vec<usize>> = OnceLock::new();
    let order = SORTED.get_or_init(|| {
        let mut order: Vec<_> = (0..BIFS.len()).collect();
        order.sort_unstable_by_key(|&i| (BIFS[i].module, BIFS[i].name, BIFS[i].arity));
        order
    });
    let at = order
        .binary_search_by_key(&(module, name, arity), |&i| {
            (BIFS[i].module, BIFS[i].name, BIFS[i].arity)
        })
        .ok()?;
    Some(&BIFS[order[at]])
}
