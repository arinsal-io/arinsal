//! Borrowed typed views over stable heap words.
use crate::{ARITY, FLOAT, MAP, NEG_BIG, POS_BIG, Term, exact_eq};
use num_bigint::{BigInt, Sign};

/// Sequential view of a possibly improper list.
pub struct ListIter {
    next: Term,
}
impl ListIter {
    /// Start at a cons cell or nil. The owning heap must remain stable.
    ///
    /// # Safety
    /// Keep the source heap live and unmoved until iteration ends.
    pub unsafe fn new(term: Term) -> Self {
        Self { next: term }
    }
    /// Return the final tail after all cons cells have been read.
    pub fn tail(&self) -> Term {
        self.next
    }
}
impl Iterator for ListIter {
    type Item = Term;
    fn next(&mut self) -> Option<Self::Item> {
        // SAFETY: The caller of `new` retains the source heap for iteration.
        let (head, tail) = unsafe { self.next.cons_ref()? };
        self.next = tail;
        Some(head)
    }
}

/// Boxed float word, borrowed from a live heap.
pub struct FloatRef<'a> {
    word: &'a u64,
}
impl FloatRef<'_> {
    /// Decode the exact IEEE 754 bit pattern.
    pub fn get(&self) -> f64 {
        f64::from_bits(*self.word)
    }
    /// Raw IEEE 754 bits.
    pub fn bits(&self) -> u64 {
        *self.word
    }
}

/// Boxed bignum digits, least significant digit first.
pub struct BigRef<'a> {
    digits: &'a [u64],
    negative: bool,
}
impl BigRef<'_> {
    /// Magnitude digits in 64-bit little-endian order.
    pub fn digits(&self) -> &[u64] {
        self.digits
    }
    /// Whether the value is negative.
    pub fn is_negative(&self) -> bool {
        self.negative
    }
    /// Convert the magnitude and sign to an owned integer.
    pub fn to_bigint(&self) -> BigInt {
        let bytes: Vec<u8> = self
            .digits
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        BigInt::from_bytes_le(
            if self.negative {
                Sign::Minus
            } else {
                Sign::Plus
            },
            &bytes,
        )
    }
}

/// Flatmap's key tuple and parallel value array.
pub struct FlatMapRef<'a> {
    keys: &'a [u64],
    values: &'a [u64],
}
impl FlatMapRef<'_> {
    /// Entry count.
    pub fn len(&self) -> usize {
        self.keys.len()
    }
    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
    /// Find a value by exact Erlang key equality.
    pub fn get(&self, key: Term) -> Option<Term> {
        self.iter()
            .find(|(candidate, _)| exact_eq(*candidate, key))
            .map(|(_, value)| value)
    }
    /// Iterate entries in the stored key order.
    pub fn iter(&self) -> impl Iterator<Item = (Term, Term)> + '_ {
        self.keys
            .iter()
            .zip(self.values)
            .map(|(key, value)| (Term(*key), Term(*value)))
    }
}
impl Term {
    /// Whether this pointer belongs to a loaded module's immutable literal area.
    pub fn is_literal(self) -> bool {
        self.is_pointer() && crate::literal::is_literal_pointer((self.bits() & !7) as *const u64)
    }

    /// Borrow a boxed float.
    ///
    /// # Safety
    /// The owning heap must remain live and unmoved while the view exists.
    pub unsafe fn float_ref<'a>(self) -> Option<FloatRef<'a>> {
        if self.header()? & 63 != FLOAT {
            return None;
        }
        // SAFETY: A float has one data word following its header.
        let word = unsafe { &*self.raw_ptr().add(1) };
        Some(FloatRef { word })
    }
    /// Borrow bignum magnitude digits.
    ///
    /// # Safety
    /// The owning heap must remain live and unmoved while the view exists.
    pub unsafe fn big_ref<'a>(self) -> Option<BigRef<'a>> {
        let header = self.header()?;
        if header & 63 != POS_BIG && header & 63 != NEG_BIG {
            return None;
        }
        // SAFETY: The header digit count determines the allocation length.
        let digits =
            unsafe { std::slice::from_raw_parts(self.raw_ptr().add(1), (header >> 6) as usize) };
        Some(BigRef {
            digits,
            negative: header & 63 == NEG_BIG,
        })
    }
    /// Borrow a flatmap's keys and values.
    ///
    /// # Safety
    /// The owning heap must remain live and unmoved while the view exists.
    pub unsafe fn flatmap_ref<'a>(self) -> Option<FlatMapRef<'a>> {
        let header = self.header()?;
        if header & 63 != MAP || self.is_hashmap() {
            return None;
        }
        // SAFETY: Flatmap words one and two contain size and a key tuple.
        let p = unsafe { self.raw_ptr() };
        // SAFETY: A valid flatmap stores its entry count and key tuple.
        let (len, keys) = unsafe { (*p.add(1) as usize, Term(*p.add(2))) };
        if keys.header()? & 63 != ARITY {
            return None;
        }
        // SAFETY: Keys tuple contains len initialized elements.
        let keys = unsafe { std::slice::from_raw_parts(keys.raw_ptr().add(1), len) };
        // SAFETY: The flatmap allocation contains len values from word three.
        let values = unsafe { std::slice::from_raw_parts(p.add(3), len) };
        Some(FlatMapRef { keys, values })
    }

    /// Return the tuple that stores a flatmap's keys, preserving its identity.
    ///
    /// Hashmaps have no shared key tuple and return `None`.
    pub fn flatmap_keys_tuple(self) -> Option<Term> {
        // Port of erts/emulator/beam/erl_map.c:3318-3324, OTP-29.1.1.
        let header = self.header()?;
        if header & 63 != MAP || self.is_hashmap() {
            return None;
        }
        // SAFETY: A flatmap stores its size and key tuple in words one and two.
        let (len, keys) = unsafe {
            let ptr = self.raw_ptr();
            (*ptr.add(1) as usize, Term(*ptr.add(2)))
        };
        let keys_header = keys.header()?;
        if keys_header & 63 != ARITY || (keys_header >> 6) as usize != len {
            return None;
        }
        Some(keys)
    }

    /// Replace a flatmap's key tuple with an equal tuple, preserving map identity.
    ///
    /// Returns false unless both tuples contain exactly the same keys.
    pub fn flatmap_replace_keys(self, keys: Term) -> bool {
        // Port of erts/emulator/beam/erl_map.c:1357-1368, OTP-29.1.1.
        let Some(current) = self.flatmap_keys_tuple() else {
            return false;
        };
        if !exact_eq(current, keys) {
            return false;
        }
        // SAFETY: A live flatmap's key pointer is word two, and `keys` is an
        // equal live tuple retained by the caller's module or process heap.
        unsafe { *self.raw_ptr().cast_mut().add(2) = keys.bits() };
        true
    }
}
