use super::{Router};
use super::Server;
use bytes::Bytes;
use super::super::prelude::*;

pub struct DumbRouter {}

impl DumbRouter {
    pub fn new() -> DumbRouter {
        DumbRouter {}
    }
}

impl Router<DumbRouter> for DumbRouter {
    fn publish(&mut self, server: &mut Server<DumbRouter>, message: Message) -> Vec<ServerEvent> {
        let mut events = vec![];

        let x = server.connections.lock().unwrap();
        for (addr, state) in x.iter() {
            let mut mutex = state.get_mutex();
            if !mutex.is_expired() {
                let next_id = mutex.next_packet_id();

                if let ConnectionState::Stream(ref paramaters) = mutex.connection_state {
                    let encrypted_message = EncryptedMessage::new_from_message(next_id, &message, paramaters);

                    if let Some(bytes) = Packet::EncryptedMessage(encrypted_message).get_bytes() {
                        events.push(ServerEvent::Packet(bytes, addr.clone()));
                    }
                } else {
                    continue;
                }
            }
        }

        events
    }

    fn send(&mut self, server: &mut Server<DumbRouter>, message: Message, id: Bytes) -> Vec<ServerEvent> {
        unimplemented!()
    }
}