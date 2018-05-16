pub use super::prelude::*;
pub use bytes::Bytes;

mod dumb_router;

pub trait Router<T>
    where T: Router<T> {
    fn publish(&mut self, server: &mut Server<T>, message: Message) -> Vec<ServerEvent> ;
    fn send_to(&mut self, server: &mut Server<T>, message: Message, mac_address: MacAddress) -> Vec<ServerEvent> ;
}

pub use self::dumb_router::DumbRouter;