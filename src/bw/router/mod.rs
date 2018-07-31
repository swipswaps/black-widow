use std::net::SocketAddr;

pub use super::prelude::*;
pub use bytes::Bytes;

mod dumb_router;

#[cfg(feature = "python-router")]
mod python_router;

pub trait Router<T>
    where T: Router<T> + Clone {
    fn start(&mut self) {}
    fn ready(&mut self, _remote: ServerRemote, _own_id: Bytes) {}
    fn set_interface_name(&mut self, _interface_name: String) {}
    fn handle_message(&self, _message: Message, _addr: SocketAddr, _id: Bytes) {}
    fn handle_packet(&self, _packet: Bytes) {}
    fn handle_new_client(&self, _addr: SocketAddr, _id: Bytes) {}
}

pub use self::dumb_router::DumbRouter;

#[cfg(feature = "python-router")]
pub use self::python_router::PythonRouter;
#[cfg(feature = "python-router")]
pub use self::python_router::use_python;