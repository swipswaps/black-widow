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
    fn queue(&mut self, event: RouterEvent) { unimplemented!() }

    fn has_queue(&mut self) -> bool { unimplemented!() }

    fn flush_queue(&mut self) -> Vec<RouterEvent> { unimplemented!() }

    fn start(&mut self) {
        unimplemented!()
    }

    fn handle_message(&mut self, message: Message) {
        unimplemented!()
    }

    fn handle_packet(&mut self, packet: Bytes) {
        unimplemented!()
    }
}