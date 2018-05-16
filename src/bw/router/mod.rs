pub use super::prelude::*;
pub use bytes::Bytes;

mod dumb_router;

pub trait Router<T>
    where T: Router<T> {
    fn publish(&mut self, server: &mut Server<T>, message: Message) -> Vec<ServerEvent> ;
    fn send(&mut self, server: &mut Server<T>, message: Message, id: Bytes) -> Vec<ServerEvent> ;
}

pub use self::dumb_router::DumbRouter;