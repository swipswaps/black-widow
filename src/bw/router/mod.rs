pub use super::prelude::*;
pub use bytes::Bytes;

mod dumb_router;

#[cfg(feature = "python-router")]
mod python_router;


pub trait Router<T>
    where T: Router<T> {
    fn start(&mut self);
    fn handle_message(&mut self, message: Message);
    fn handle_packet(&mut self, packet: Bytes);
}

pub use self::dumb_router::DumbRouter;

#[cfg(feature = "python-router")]
pub use self::python_router::PythonRouter;