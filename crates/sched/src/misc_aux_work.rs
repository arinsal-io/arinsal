// Port of erts/emulator/beam/erl_process.c (erts_schedule_misc_aux_work), OTP-29.1.1.

use std::any::Any;

/// An owned, type-erased aux-work argument. The queue entry consumes it exactly once.
pub(crate) type Argument = Box<dyn Any + Send + 'static>;

/// Box an argument before publishing its matching aux-work function pointer.
pub(crate) fn boxed_arg<T: Any + Send + 'static>(value: T) -> Argument {
    Box::new(value)
}

/// Recover the concrete argument paired with this queue entry's function pointer.
pub(crate) fn take_boxed_arg<T: Any + Send + 'static>(arg: Argument) -> Box<T> {
    match arg.downcast::<T>() {
        Ok(value) => value,
        Err(_) => unreachable!("misc aux work function and owned argument must match"),
    }
}
