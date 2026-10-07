//! Definition of C-ABI exports with a single `#[unsafe(no_mangle)]` site.
//!
//! `export!` defines each function as an `extern "C"` symbol of the executable
//! and a table of `(name, address)` pairs so the executable can keep them linked
//! (see [`crate::ensure_exports`]) and the API table test can check them.

macro_rules! export {
    (
        table $table:ident;
        $(
            $(#[$meta:meta])*
            fn $name:ident($($arg:ident: $ty:ty),* $(,)?) $(-> $ret:ty)? $body:block
        )*
    ) => {
        $(
            $(#[$meta])*
            #[unsafe(no_mangle)]
            pub extern "C" fn $name($($arg: $ty),*) $(-> $ret)? $body
        )*
        pub(crate) fn $table() -> Vec<(&'static str, usize)> {
            vec![$((stringify!($name), $name as *const () as usize)),*]
        }
    };
    ($(#[$meta:meta])* static $name:ident: $ty:ty = $value:expr;) => {
        $(#[$meta])*
        #[unsafe(no_mangle)]
        pub static $name: $ty = $value;
    };
}
