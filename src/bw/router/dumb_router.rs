use super::Router;
use super::Server;
use super::super::prelude::*;


use bytes::Bytes;
use std::mem;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use multiqueue::MPMCSender as Sender;


#[derive(Clone)]
pub struct DumbRouter {
    remote: Option<ServerRemote>,
}

impl DumbRouter {
    pub fn new() -> DumbRouter {
        DumbRouter {
            remote: None
        }
    }
}

impl Router<DumbRouter> for DumbRouter {
    fn handle_message(&self, message: Message, addr: SocketAddr, id: Bytes) {
        if let Some(ref remote) = &self.remote {
            if message.message_type == MessageType::Ethernet {
                remote.write_packet(message.payload);
            }
        }
    }

    fn handle_packet(&self, packet: Bytes) {
        if let Some(ref remote) = &self.remote {
            remote.publish_message(Message::new(MessageType::Ethernet, packet));
        }
    }

    fn ready(&mut self, remote: ServerRemote) {
        self.remote = Some(remote)
    }
}