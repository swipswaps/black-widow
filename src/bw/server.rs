use std::net::SocketAddr;
use std::io::Error;
use std::time::Instant;
use std::collections::HashMap;
use tokio::prelude::*;
use futures::stream::{Stream, SplitStream, SplitSink};
use bytes::Bytes;

use super::packet::EthernetPacket;

#[derive(Debug)]
pub enum ServerEvent {
    Tunnel(Bytes),
    Packet(Bytes, SocketAddr),
}

pub struct ConnectionInfo {
    addr: SocketAddr,
    last_update: Instant,
}

impl ConnectionInfo {
    pub fn new(addr: SocketAddr) -> ConnectionInfo {
        ConnectionInfo {
            addr,
            last_update: Instant::now(),
        }
    }

    pub fn bump(&self) {
        self.last_update = Instant::now();
    }

    pub fn is_expired(&self) {
        Instant::now().duration_since(self.last_update).as_secs() > 60;
    }
}

pub struct Server {
    queue: Vec<ServerEvent>,
    closed: bool,
    connections: HashMap<SocketAddr, Connection>,
}

impl Server {
    pub fn new() -> Server {
        Server {
            queue: vec![],
            closed: false,
            connections: HashMap::new(),
        }
    }

    fn queue_event(&self, event: ServerEvent) {
        self.queue.push(event)
    }

    fn on_tunnel(&mut self, data: Bytes) {}

    fn on_dht_krpc(&self, data: Bytes) {
        // TODO
    }

    fn on_message(&self, data: Bytes, connection_info: &mut ConnectionInfo) {
        connection_info.bump();

        if data[0] == 101 { // 'e'
            self.handle_key_exchange(data, connection_info);
            return;
        }
    }

    fn handle_key_exchange(data: Bytes, connection_info: &mut ConnectionInfo) {

    }

    fn on_packet(&mut self, data: Bytes, addr: SocketAddr) {
        if data[0] == 100 { // 'd'
            // No ConnectionInfo needed for krpc
            self.on_dht_krpc(data);
            return;
        }

        let mut connection_info: ConnectionInfo = match self.connections.get_mut(addr) {
            Some(info) => info,
            None => ConnectionInfo::new(addr)
        };

        self.on_message(data, connection_info)
    }

    fn on_event(&mut self, event: ServerEvent) {
        println!("Got event: {:?}", event);

        match event {
            ServerEvent::Tunnel(data) => self.on_tunnel(data),
            ServerEvent::Packet(data, addr) => self.on_packet(data, addr),
        }
    }
}

impl Stream for Server {
    type Item = ServerEvent;
    type Error = Error;

    fn poll(&mut self) -> Result<Async<Option<<Self as Stream>::Item>>, <Self as Stream>::Error> {
        if self.queue.len() == 0 {
            return Ok(Async::Ready(None));
        }

        Ok(Async::Ready(Some(self.queue.remove(0))))
    }
}

impl Sink for Server {
    type SinkItem = ServerEvent;
    type SinkError = Error;

    fn start_send(&mut self, item: <Self as Sink>::SinkItem) -> Result<AsyncSink<<Self as Sink>::SinkItem>, <Self as Sink>::SinkError> {
        if self.closed {
            return Ok(AsyncSink::NotReady(item));
        }

        self.on_event(item);

        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Result<Async<()>, <Self as Sink>::SinkError> {
        if self.closed {
            return Ok(Async::NotReady);
        }

        Ok(Async::Ready(()))
    }

    fn close(&mut self) -> Result<Async<()>, <Self as Sink>::SinkError> {
        self.closed = false;

        Ok(Async::Ready(()))
    }
}