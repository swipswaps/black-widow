use super::{Router};
use super::Server;
use bytes::Bytes;
use super::super::prelude::*;
use std::mem;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct DumbRouter {
    queue: Vec<RouterEvent>,
    mac_address_map: HashMap<MacAddress, Vec<u8>>,
    ip_address_map: HashMap<IpAddr, Vec<MacAddress>>,
}

impl DumbRouter {
    pub fn new() -> DumbRouter {
        DumbRouter {
            queue: vec![],
            mac_address_map: HashMap::new(),
            ip_address_map: HashMap::new(),
        }
    }
}

impl Router<DumbRouter> for DumbRouter {
    fn queue(&mut self, event: RouterEvent) {
        self.queue.push(event);
    }

    fn has_queue(&mut self) -> bool { self.queue.len() > 0 }

    fn flush_queue(&mut self) -> Vec<RouterEvent> { mem::replace(&mut self.queue, vec![]) }

    fn start(&mut self) {}

    fn handle_message(&mut self, message: Message) {
        if message.message_type == MessageType::Ethernet {
            self.queue(RouterEvent::Packet(message.payload.clone()))
        }
    }

    fn handle_packet(&mut self, packet: Bytes) {
        self.queue(RouterEvent::PublishMessage(Message::new(MessageType::Ethernet, packet.clone())));
    }
}