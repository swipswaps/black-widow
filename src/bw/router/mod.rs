use std::net::SocketAddr;

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
    fn ready(&mut self) {}
    fn queue(&mut self, event: RouterEvent);
    fn has_queue(&mut self) -> bool;
    fn flush_queue(&mut self) -> Vec<RouterEvent>;
    fn set_interface_name(&mut self, interface_name: String) {}
}

pub use self::dumb_router::DumbRouter;

pub enum RouterEvent {
    PublishMessage(Message),
    SendMessageToClient(Message, Vec<u8>),
    SendMessageToAddr(Message, SocketAddr),
    Packet(Bytes),
}

#[cfg(feature = "python-router")]
pub use self::python_router::PythonRouter;