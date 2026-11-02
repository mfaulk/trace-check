//! The deliberately narrow set of secret representations that can be marked.
//!
//! Marking tells Memcheck that a *byte range* is undefined. A type is therefore
//! only supported when all of its secret bytes live in the storage the borrow
//! points at.
//!
//! This is where a generic API would be actively dangerous. `Vec<u8>`'s own
//! storage is a pointer, a length and a capacity; marking it marks none of the
//! heap buffer. A blanket `impl<T> MarkSecret for T` would compile, run, report
//! no leak, and have checked nothing. So the trait is sealed and implemented
//! only for representations that have been reasoned about and tested.

use trace_check_secret::Secret;

/// A guard holding the marking for the duration of an analyzed call.
pub struct SecretGuard<'a> {
    _inner: Secret<'a, [u8]>,
}

/// Implemented for representations whose secret bytes are entirely within the
/// borrowed storage.
///
/// | Type | Marked |
/// | --- | --- |
/// | `[u8; N]` | all `N` bytes |
/// | `[u8]` | all `len` bytes — pass `vec.as_slice()` |
/// | `u8`…`u128`, `usize` and signed equivalents | the scalar's bytes |
///
/// `Vec<u8>`, `String`, `Box<T>` and arbitrary structs are **not** implemented.
/// For a `Vec`, pass `vec.as_slice()`; the slice's bytes are the heap buffer.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a supported secret representation",
    label = "this type's secret bytes are not all in its own storage",
    note = "supported: [u8; N], scalar integers, and &[u8] via `secret_bytes = ...`",
    note = "for a Vec<u8> or String, pass `secret_bytes = value.as_slice()` or             `value.as_bytes()`: marking a Vec would mark its pointer, length and             capacity and none of the heap data, which would report `no leak` for             bytes that were never analyzed"
)]
pub trait MarkSecret: sealed::Sealed {
    /// Marks this value's bytes until the returned guard is dropped.
    fn mark(&self) -> SecretGuard<'_>;

    /// Number of bytes this implementation marks, for reporting.
    fn marked_len(&self) -> usize;
}

mod sealed {
    pub trait Sealed {}
}

/// Marks a byte range and makes the compiler forget what it contains.
///
/// The `black_box` is load-bearing, not decoration. Marking tells Memcheck the
/// bytes are undefined, but if the optimizer already knows the value it will
/// pass an immediate and never read the marked storage — so the secret never
/// reaches the code under test and the run observes nothing. That is a false
/// negative, and it is the failure the positive control cannot catch, because
/// calibration marks its own byte and succeeds regardless.
///
/// Passing the reference through `black_box` forces the compiler to assume the
/// memory may have been accessed through that pointer, so later reads must come
/// from memory.
fn mark_bytes(bytes: &[u8]) -> SecretGuard<'_> {
    let guard = SecretGuard {
        _inner: Secret::new(bytes),
    };
    let _ = std::hint::black_box(bytes);
    guard
}

impl<const N: usize> sealed::Sealed for [u8; N] {}
impl<const N: usize> MarkSecret for [u8; N] {
    fn mark(&self) -> SecretGuard<'_> {
        mark_bytes(self.as_slice())
    }
    fn marked_len(&self) -> usize {
        N
    }
}

impl sealed::Sealed for [u8] {}
impl MarkSecret for [u8] {
    fn mark(&self) -> SecretGuard<'_> {
        mark_bytes(self)
    }
    fn marked_len(&self) -> usize {
        self.len()
    }
}

/// Scalars are marked through their own byte representation. Sound because an
/// integer has no indirection: every bit of the secret is in those bytes.
macro_rules! impl_scalar {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl sealed::Sealed for $ty {}
            impl MarkSecret for $ty {
                fn mark(&self) -> SecretGuard<'_> {
                    // SAFETY: an integer is plain old data with no padding and
                    // no interior references, so its `size_of` bytes are a
                    // valid initialized byte range for the borrow's lifetime.
                    let bytes = unsafe {
                        core::slice::from_raw_parts(
                            (self as *const $ty).cast::<u8>(),
                            core::mem::size_of::<$ty>(),
                        )
                    };
                    mark_bytes(bytes)
                }
                fn marked_len(&self) -> usize {
                    core::mem::size_of::<$ty>()
                }
            }
        )+
    };
}

impl_scalar!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize);

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed-size array marks every one of its bytes.
    #[test]
    fn array_marks_all_bytes() {
        let tag = [7u8; 32];
        assert_eq!(tag.marked_len(), 32);
        let guard = tag.mark();
        // Marking never alters the value.
        assert_eq!(tag, [7u8; 32]);
        drop(guard);
        assert_eq!(tag, [7u8; 32]);
    }

    /// A slice marks its contents, which is what makes `vec.as_slice()` the
    /// correct way to mark heap-allocated secret bytes.
    #[test]
    fn slice_marks_its_contents_not_a_header() {
        let owned = vec![9u8; 100];
        let slice: &[u8] = owned.as_slice();
        assert_eq!(
            slice.marked_len(),
            100,
            "a slice must mark its elements, not a 24-byte Vec header"
        );
        let _guard = slice.mark();
        assert_eq!(owned.len(), 100);
    }

    /// An empty slice is accepted and marks nothing.
    #[test]
    fn empty_slice_marks_nothing() {
        let empty: &[u8] = &[];
        assert_eq!(empty.marked_len(), 0);
        let _guard = empty.mark();
    }

    /// Scalars mark exactly their width, so a secret index or counter can be
    /// declared without wrapping it in an array.
    #[test]
    fn scalars_mark_their_own_width() {
        assert_eq!(1u8.marked_len(), 1);
        assert_eq!(1u16.marked_len(), 2);
        assert_eq!(1u32.marked_len(), 4);
        assert_eq!(1u64.marked_len(), 8);
        assert_eq!(1u128.marked_len(), 16);
        assert_eq!(1usize.marked_len(), core::mem::size_of::<usize>());
        assert_eq!((-1i64).marked_len(), 8);
    }

    /// Marking a scalar leaves its value intact.
    #[test]
    fn scalar_marking_preserves_the_value() {
        let secret: u32 = 0xdead_beef;
        let guard = secret.mark();
        assert_eq!(secret, 0xdead_beef);
        drop(guard);
        assert_eq!(secret, 0xdead_beef);
    }

    /// Several secrets can be marked at once and all guards held together,
    /// which is what `assert_constant_time!` does for `secrets = [..]`.
    #[test]
    fn multiple_secrets_can_be_marked_together() {
        let key = [1u8; 16];
        let index = 42u8;
        let secrets: Vec<&dyn MarkSecret> = vec![&key, &index];
        let guards: Vec<_> = secrets.iter().map(|s| s.mark()).collect();
        assert_eq!(guards.len(), 2);
        assert_eq!(secrets[0].marked_len(), 16);
        assert_eq!(secrets[1].marked_len(), 1);
    }
}
