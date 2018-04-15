use std::net::SocketAddr;
use std::io::Error;
use std::mem;
use std::u64;
use std::sync::{Mutex, MutexGuard, Arc};
use std::time::Instant;
use std::collections::HashMap;

use tokio::prelude::*;
use futures::stream::{Stream, SplitStream, SplitSink};
use bytes::{Bytes, BytesMut, ByteOrder};
use byteorder::BigEndian;
use ring::agreement::{EphemeralPrivateKey, X25519, PUBLIC_KEY_MAX_LEN, agree_ephemeral};
use ring::rand::{SecureRandom, SystemRandom};
use ring;
use untrusted;


use super::packet::EthernetPacket;
use super::protocol::*;
use super::config::Config;

#[derive(Debug)]
pub enum ServerEvent {
    Tunnel(Bytes),
    Packet(Bytes, SocketAddr),
    Control(String),
}

pub enum ConnectionState {
    Null,
    KeyExchange(EphemeralPrivateKey),
    Stream(EncryptionParameters),
}

impl ConnectionState {
    pub fn is_null(&self) -> bool {
        match *self {
            ConnectionState::Null => {
                true
            }

            _ => {
                false
            }
        }
    }
}

pub struct ConnectionInfo {
    addr: SocketAddr,
    last_update: Instant,
    connection_state: ConnectionState,
    public_key: Option<Bytes>,
    packet_id: u64,
}

impl ConnectionInfo {
    pub fn new(addr: SocketAddr) -> ConnectionInfo {
        ConnectionInfo {
            public_key: None,
            addr,
            last_update: Instant::now(),
            connection_state: ConnectionState::Null,
            packet_id: 0,
        }
    }

    pub fn bump(&mut self) {
        self.last_update = Instant::now();
    }

    pub fn next_packet_id(&mut self) -> u64 {
        if self.packet_id == 0 {
            let mut x = vec![0u8; 8];
            SystemRandom::new().fill(&mut x);

            self.packet_id = BigEndian::read_u64(&x);
        }

        self.packet_id = self.packet_id.overflowing_add(1).0;

        // Should never been 0
        if self.packet_id == 0 {
            self.packet_id = 1;
        }

        self.packet_id
    }

    pub fn is_expired(&self) -> bool {
        Instant::now().duration_since(self.last_update).as_secs() > 60
    }
}

#[derive(Clone)]
struct MutexConnectionInfo(Arc<Mutex<ConnectionInfo>>);

impl MutexConnectionInfo {
    pub fn new(addr: SocketAddr) -> MutexConnectionInfo {
        let info = ConnectionInfo::new(addr);
        return MutexConnectionInfo::wrap(info);
    }

    pub fn wrap(info: ConnectionInfo) -> MutexConnectionInfo {
        return MutexConnectionInfo(Arc::new(Mutex::new(info)));
    }

    fn get_mutex(&self) -> MutexGuard<ConnectionInfo> { self.0.lock().unwrap() }

    pub fn bump(&self) {
        self.get_mutex().bump();
    }
}

pub struct Server {
    queue: Vec<ServerEvent>,
    closed: bool,
    connections: Arc<Mutex<HashMap<SocketAddr, MutexConnectionInfo>>>,
    config: Config,
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

    fn on_tunnel(&mut self, data: Bytes) {
        let mut events = vec![];
        {
            let x = self.connections.lock().unwrap();
            let message = Message::new(1, data.clone());

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
        }

        for event in events {
            self.queue_event(event);
        }
    }

    fn on_dht_krpc(&self, data: Bytes, addr: SocketAddr) {
        // TODO
    }

    fn handle_message(&mut self, message: Message, connection_info: MutexConnectionInfo) {
        if message.message_type == 1 {
            self.queue_event(ServerEvent::Tunnel(message.payload));
        }
    }

    fn on_message(&mut self, encrypted_message: EncryptedMessage, connection_info: MutexConnectionInfo) {
        let mut parameters: Option<EncryptionParameters> = None;

        {
            let info = connection_info.get_mutex();
            if let ConnectionState::Stream(ref para) = info.connection_state {
                parameters = Some(para.clone());
            }
        }

        if let Some(parameters) = parameters {
            let message = encrypted_message.decrypt(&parameters);
            if message.is_none() {
                return;
            }

            let message = message.unwrap();
            if !message.verify(&parameters) {
                return;
            }

            {
                let mut info = connection_info.get_mutex();
                info.bump();
            }


            self.handle_message(message, connection_info);
        }
    }

    fn handle_key_exchange(&mut self, key_exchange: KeyExchange, connection_info: MutexConnectionInfo) {
        if !key_exchange.verify(&self.config) {
            return;
        }

        connection_info.bump();

        let mut info = connection_info.get_mutex();

        let state = mem::replace(&mut info.connection_state, ConnectionState::Null);

        match state {
            ConnectionState::KeyExchange(key) => {
                match key_exchange.derive_encryption_parameters(key, &self.config) {
                    None => {
                        info.connection_state = ConnectionState::Null;
                    }

                    Some(paramaters) => {
                        info.connection_state = ConnectionState::Stream(paramaters)
                    }
                }
            }

            _ => {
                if let Ok((exchange, key)) = KeyExchange::new_key_exchange(&self.config) {
                    if let Some(parameters) = key_exchange.derive_encryption_parameters(key, &self.config) {
                        if let Some(bytes) = Packet::KeyExchange(exchange).get_bytes() {
                            info.connection_state = ConnectionState::Stream(parameters);
                            self.queue_event(ServerEvent::Packet(bytes, info.addr.clone()));
                        } else {
                            info.connection_state = ConnectionState::Null;
                        }
                    } else {
                        info.connection_state = ConnectionState::Null;
                    }
                } else {
                    info.connection_state = ConnectionState::Null;
                }
            }
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
        match Packet::from_bytes(data) {
            Some(Packet::MainlineDHT(data)) => {
                self.on_dht_krpc(data, addr);
            }

            Some(Packet::KeyExchange(key_exchange)) => {

                if let Some(connection_info) = self.get_connection_info(addr) {
                    self.handle_key_exchange(key_exchange, connection_info);
                }
            }

            Some(Packet::EncryptedMessage(encrypted_message)) => {
                if let Some(connection_info) = self.get_connection_info(addr) {
                    self.on_message(encrypted_message, connection_info);
                }
            }

            _ => {}
        }
    }

    fn on_event(&mut self, event: ServerEvent) {
        println!("Got event: {:?}", event);

        match event {
            ServerEvent::Tunnel(data) => self.on_tunnel(data),
            ServerEvent::Packet(data, addr) => self.on_packet(data, addr),
            ServerEvent::Control(data) => self.on_control(data),
        }
    }

    fn on_control(&mut self, data: String) {
        if data.starts_with("connect ") {
            let try = data[8..].trim();

            if let Ok(x) = try.parse::<SocketAddr>() {
                self.connect(x);
                self.queue_event(ServerEvent::Control(String::from("Ok\n")));
            } else {
                self.queue_event(ServerEvent::Control(String::from("No\n")));
            }
        }
    }

    pub fn connect(&mut self, addr: SocketAddr) {
        {
            let connections = self.connections.lock().unwrap();
            if connections.contains_key(&addr) && connections[&addr].get_mutex().connection_state.is_null() {
                return;
            }
        }

        if let Ok((exchange, key)) = KeyExchange::new_key_exchange(&self.config) {
            let mut info = ConnectionInfo::new(addr.clone());

            info.connection_state = ConnectionState::KeyExchange(key);

            if let Some(bytes) = Packet::KeyExchange(exchange).get_bytes() {
                self.queue_event(ServerEvent::Packet(bytes, addr.clone()));
            } else {
                return;
            }

            let mut conns = self.connections.lock().unwrap();
            conns.insert(addr, MutexConnectionInfo::wrap(info));
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