use super::{Router};
use super::Server;
use bytes::Bytes;
use super::super::prelude::*;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct DumbRouter {
    mac_address_map: HashMap<MacAddress, Vec<u8>>,
    ip_address_map: HashMap<IpAddr, Vec<MacAddress>>,
}

impl DumbRouter {
    pub fn new() -> DumbRouter {
        DumbRouter {
            mac_address_map: HashMap::new(),
            ip_address_map: HashMap::new(),
        }
    }
}

impl Router<DumbRouter> for DumbRouter {
    fn publish(&mut self, server: &mut Server<DumbRouter>, message: Message) -> Vec<ServerEvent> {
        let mut events = vec![];

        for state in server.connections.iter() {
            let mut mutex = state.get_mutex();
            if !mutex.is_expired() {
                let next_id = mutex.next_packet_id();

                if let ConnectionState::Stream(ref paramaters) = mutex.connection_state {
                    let encrypted_message = EncryptedMessage::new_from_message(next_id, &message, paramaters);

                    if let Some(bytes) = Packet::EncryptedMessage(encrypted_message).get_bytes() {
                        events.push(ServerEvent::Packet(bytes, mutex.addr.clone()));
                    }
                } else {
                    continue;
                }
            }
        }

        events
    }

    fn send_to(&mut self, server: &mut Server<DumbRouter>, message: Message, mac_address: MacAddress) -> Vec<ServerEvent> {
        unimplemented!()
    }
}