//! Layout of a message node as generated code reads it: the one `unsafe` of the message queue
//! module.

use super::*;

/// `offsetof(ErtsMessage, m[0])`: byte offset of the term of a message in its queue node, which
/// generated code loads after peeking the node at `sig_qs.save`. The variant's place in
/// `Payload` is a property of the type, measured on a value built at compile time.
// Port of erts/emulator/beam/erl_message.h (`ErtsMessage`: `m[0]` is ERL_MESSAGE_TERM),
// OTP-29.1.1.
pub(crate) const MESSAGE_TERM_OFFSET: usize = {
    let event = Event {
        from: Pid::from_data(0),
        payload: Payload::Message(Message::immediate(Term::NIL)),
    };
    let term = match &event.payload {
        Payload::Message(message) => std::ptr::addr_of!(message.term),
        _ => unreachable!(),
    };
    // SAFETY: both pointers are into `event`, which is alive here.
    let offset = unsafe { term.byte_offset_from(&raw const event) };
    std::mem::forget(event);
    std::mem::offset_of!(arinsal_term::message::SignalNode<Event<Message>>, value) + offset as usize
};
