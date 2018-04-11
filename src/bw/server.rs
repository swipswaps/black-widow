use std::net::SocketAddr;
use std::io::Error;
use std::sync::{Mutex, Arc};
use std::time::Instant;
use std::collections::HashMap;
use tokio::prelude::*;
use futures::stream::{Stream, SplitStream, SplitSink};
use bytes::{Bytes, BytesMut};
use ring::agreement::{EphemeralPrivateKey, X25519, PUBLIC_KEY_MAX_LEN, agree_ephemeral};
use ring::rand;
use ring;
use untrusted;

use super::packet::EthernetPacket;
use super::protocol::{get_frame_type, KeyExchange, FrameType, Request, Answer};
use super::config::Config;

#[derive(Debug)]
pub enum ServerEvent {
    Tunnel(Bytes),
    Packet(Bytes, SocketAddr),
}

pub enum EncryptionState {
    Null,
    DH(EphemeralPrivateKey, Bytes),
    Stream(Bytes),
}

pub struct ConnectionInfo {
    addr: SocketAddr,
    last_update: Instant,
    encryption_state: EncryptionState,
}

impl ConnectionInfo {
    pub fn new(addr: SocketAddr) -> ConnectionInfo {
        ConnectionInfo {
            addr,
            last_update: Instant::now(),
            encryption_state: EncryptionState::Null,
        }
    }

    pub fn bump(&mut self) {
        self.last_update = Instant::now();
    }

    pub fn is_expired(&self) {
        Instant::now().duration_since(self.last_update).as_secs() > 60;
    }
}

#[derive(Clone)]
struct MutexConnectionInfo(Arc<Mutex<ConnectionInfo>>);

impl MutexConnectionInfo {
    pub fn new(addr: SocketAddr) -> MutexConnectionInfo {
        let info = ConnectionInfo::new(addr);

        return MutexConnectionInfo(Arc::new(Mutex::new(info)));
    }

    pub fn bump(&self) {
        let mut item = self.0.lock().unwrap();
        item.bump();
    }
}

pub struct Server {
    queue: Vec<ServerEvent>,
    closed: bool,
    connections: Arc<Mutex<HashMap<SocketAddr, MutexConnectionInfo>>>,
    config: Config
}

impl Server {
    pub fn new(config: Config) -> Server {
        Server {
            queue: vec![],
            closed: false,
            connections: Arc::new(Mutex::new(HashMap::new())),
            config,
        }
    }

    fn queue_event(&mut self, event: ServerEvent) {
        self.queue.push(event)
    }

    fn on_tunnel(&mut self, data: Bytes) {}

    fn on_dht_krpc(&self, data: Bytes) {
        // TODO
    }

    fn on_message(&mut self, data: Bytes, connection_info: MutexConnectionInfo) {
        connection_info.bump();
        println!("Got message with identifier '{:?}'", data[0]);

        match get_frame_type(data.slice(0, 1)) {
            FrameType::KeyExchange => self.handle_key_exchange(data, connection_info),
            _ => {}
        }
    }

    fn handle_key_exchange(&mut self, data: Bytes, connection_info: MutexConnectionInfo) {
        let message = KeyExchange::from_bytes(data.slice_from(1));
        println!("KeyExchange: {:?}", message);

        match message {
            Some(KeyExchange::Request(req)) => {
                if let Ok(key) = EphemeralPrivateKey::generate(&X25519, &rand::SystemRandom::new()) {
                    let mut conn = connection_info.0.lock().unwrap();

                    let mut pub_key_mut: Vec<u8> = vec![0 as u8; key.public_key_len()];

                    key.compute_public_key(&mut pub_key_mut).unwrap();

                    let pub_key = Bytes::from(pub_key_mut);

                    let sign_key: ring::hmac::SigningKey = ring::hmac::SigningKey::new(&ring::digest::SHA512, b"black-widow");

                    let pw = agree_ephemeral(key, &X25519, untrusted::Input::from(&req.public_key[..]), ring::error::Unspecified, |key_material| {
                        let mut pw = BytesMut::with_capacity(64);
                        ring::hkdf::expand(&sign_key, key_material, &mut pw[..]);

                        Ok(pw.freeze())
                    });

                    if

                    conn.encryption_state = EncryptionState::Stream(pw.unwrap());

                    let ans = Answer {
                        features: 0,
                        version: 0,
                        proof: Bytes::new(),
                        secret: Bytes::new(),
                        public_key: pub_key.clone(),
                    };

                    let mut out = vec![0; 1000];

                    let size = ans.to_bytes(&mut out);

                    let out = Bytes::from(&out[..size]);

                    self.queue_event(ServerEvent::Packet(out, conn.addr));
                } else {
                    println!("Failed generating ECDH key");
                }
            }
            _ => {}
        }
    }

    fn get_connection_info(&self, addr: SocketAddr) -> Option<MutexConnectionInfo> {
        let mut connection_map = self.connections.lock().unwrap();

        if !connection_map.contains_key(&addr) {
            let new_info = MutexConnectionInfo::new(addr);
            connection_map.insert(addr, new_info);
        }

        let val = connection_map.get(&addr);

        if let Some(x) = val {
            return Some(x.clone());
        }

        None
    }

    fn on_packet(&mut self, data: Bytes, addr: SocketAddr) {
        match get_frame_type(data.slice(0, 1)) {
            FrameType::MainlineDHT => self.on_dht_krpc(data),
            _ => {
                if let Some(connection_info) = self.get_connection_info(addr) {
                    self.on_message(data, connection_info);
                } else {
                    println!("Unable to fetch connection info for {:?}", addr);
                }
            }
        }
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
            return Ok(Async::NotReady);
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