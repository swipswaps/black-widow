use std::net::SocketAddr;
use std::io::Error;
use tokio::prelude::*;
use futures::stream::{Stream, SplitStream, SplitSink};
use bytes::Bytes;

use super::packet::EthernetPacket;

#[derive(Debug)]
pub enum ServerEvent {
    Tunnel(Vec<u8>),
    Packet(Vec<u8>, SocketAddr),
}


pub struct Server {
    queue: Vec<ServerEvent>,
    closed: bool,
}

impl Server {
    pub fn new() -> Server {
        Server {
            queue: vec![],
            closed: false,
        }
    }

    fn on_event(&mut self, event: ServerEvent) {
        println!("Got event: {:?}", event);

        if let ServerEvent::Tunnel(data) = event {
            let bytes = Bytes::from(&data[4..]);
            let packet = EthernetPacket::from_bytes(bytes);
            println!("Got packet in tunnel: {:?}", packet);

        }
    }
}

impl Stream for Server {
    type Item = ServerEvent;
    type Error = Error;

    fn poll(&mut self) -> Result<Async<Option<<Self as Stream>::Item>>, <Self as Stream>::Error> {
        if self.queue.len() == 0 {
            return Ok(Async::Ready(None))
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