//! Magic reference terms: the `ErtsMRefThing` side of a magic binary.

use crate::raw::magic_bin::thing_block;
use crate::{MagicBin, MagicRef};

impl crate::Term {
    /// `erts_magic_ref_save_bin` for a reference term; other terms are left alone.
    pub fn save_magic_ref(self) {
        if let Some(owner) = self.magic_owner() {
            owner.save_in_table();
        }
    }

    /// A counted reference to the magic owner of a live magic reference term, like
    /// `erts_refc_inc` on `ErtsMRefThing.mb`.
    pub fn magic_owner(self) -> Option<MagicBin> {
        self.magic_word()
            .map(|word| MagicBin::thing_owner(word, true))
    }

    /// Run `visit` on the payload of a magic reference, borrowed from the term without touching
    /// the reference count. `None` when the term is not a magic reference or its payload is
    /// not a `T`.
    // Port of erts/emulator/beam/erl_bif_unique.c / erl_db.c (erts_magic_ref2bin and the
    // `ERTS_MAGIC_BIN_DATA` read in db_get_table_aux), OTP-29.1.1: the magic binary is read
    // through the reference thing, with no refcount write.
    pub fn with_magic_payload<T: crate::MagicPayload, R>(
        self,
        visit: impl FnOnce(&T) -> R,
    ) -> Option<R> {
        // SAFETY: like every `Term` accessor taking a pointer-tagged term, the caller holds the
        // term in a live heap (a BIF argument or register), which retains the magic binary on
        // its off-heap list for the duration of this call.
        let magic = unsafe { self.magic_ref() }?;
        magic.downcast_ref::<T>().map(visit)
    }

    /// Borrow the magic binary of a live reference term.
    ///
    /// # Safety
    /// The term's heap and its off-heap owners must stay live for the borrow.
    pub unsafe fn magic_ref<'a>(self) -> Option<&'a MagicRef> {
        let word = self.magic_word()?;
        // SAFETY: forwarded caller contract.
        Some(unsafe { thing_block(word) })
    }
}

/// An [`arinsal_etf::MagicHandle`] that keeps `owner` alive.
pub fn magic_handle(owner: MagicBin) -> arinsal_etf::MagicHandle {
    arinsal_etf::MagicHandle::new(owner.id(), std::sync::Arc::new(owner))
}

/// An [`arinsal_etf::MagicHandle`] that does not keep the binary alive, for a resource's
/// reference to itself.
pub fn magic_handle_weak(id: u64, owner: crate::MagicWeak) -> arinsal_etf::MagicHandle {
    arinsal_etf::MagicHandle::new(id, std::sync::Arc::new(owner))
}

/// The magic binary an [`arinsal_etf::MagicHandle`] names, unless a weak handle outlived it.
pub fn magic_handle_owner(handle: &arinsal_etf::MagicHandle) -> Option<MagicBin> {
    let owner = handle.owner();
    if let Some(strong) = owner.downcast_ref::<MagicBin>() {
        return Some(strong.clone());
    }
    owner.downcast_ref::<crate::MagicWeak>()?.upgrade()
}
