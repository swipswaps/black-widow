use std::net::SocketAddr;
use std::io::Error;
use std::mem;
use std::u64;
use std::sync::{Mutex, MutexGuard, Arc};
use std::time::Instant;
use std::collections::HashMap;
use std::collections::hash_map::Values;

use tokio::prelude::*;
use futures::stream::{Stream, SplitStream, SplitSink};
use bytes::{Bytes, BytesMut, ByteOrder};
use byteorder::BigEndian;
use ring::agreement::{EphemeralPrivateKey, X25519, PUBLIC_KEY_MAX_LEN, agree_ephemeral};
use ring::rand::{SecureRandom, SystemRandom};
use ring;
use untrusted;


use super::prelude::*;

#[macro_use] use super::macros;

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
    pub addr: SocketAddr,
    pub last_update: Instant,
    pub connection_state: ConnectionState,
    pub public_key: Option<Bytes>,
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
pub struct MutexConnectionInfo(Arc<Mutex<ConnectionInfo>>);

impl MutexConnectionInfo {
    pub fn new(addr: SocketAddr) -> MutexConnectionInfo {
        let info = ConnectionInfo::new(addr);
        return MutexConnectionInfo::wrap(info);
    }

    pub fn wrap(info: ConnectionInfo) -> MutexConnectionInfo {
        return MutexConnectionInfo(Arc::new(Mutex::new(info)));
    }

    pub fn get_mutex(&self) -> MutexGuard<ConnectionInfo> { self.0.lock().unwrap() }

    pub fn bump(&self) {
        self.get_mutex().bump();
    }
}

pub struct ConnectionCollection {
    pointer: usize,
    by_public: HashMap<Vec<u8>, usize>,
    by_addr: HashMap<SocketAddr, usize>,
    map: HashMap<usize, MutexConnectionInfo>,
}

impl ConnectionCollection {
    pub fn new() -> ConnectionCollection {
        ConnectionCollection {
            pointer: 0,
            by_addr: HashMap::new(),
            by_public: HashMap::new(),
            map: HashMap::new(),
        }
    }

    pub fn add(&mut self, info: ConnectionInfo) -> MutexConnectionInfo {
        let addr = info.addr.clone();
        let key = info.public_key.clone();

        let index = self.pointer;
        let mutex = MutexConnectionInfo::wrap(info);
        self.pointer += 1;
        let new_mutex = mutex.clone();

        self.map.insert(index, mutex);

        if let Some(old_index) = self.by_addr.remove(&addr) {
            self.remove_connection_by_pointer(old_index);
        }

        self.by_addr.insert(addr, index);

        if let Some(key) = key {
            if let Some(old_index) = self.by_public.remove(&key.to_vec()) {
                self.remove_connection_by_pointer(old_index);
            }

            self.by_public.insert(key.to_vec(), index);
        }

        new_mutex
    }

    pub fn get_by_addr(&mut self, addr: SocketAddr) -> Option<MutexConnectionInfo> {
        let res = {
            if let Some(x) = self.by_addr.get(&addr) {
                Some(x.clone())
            } else {
                None
            }
        };

        if let Some(item) = res {
            self.get_by_pointer(item)
        } else {
            None
        }
    }

    pub fn get_by_public_key(&mut self, public: Bytes) -> Option<MutexConnectionInfo> {
        let res = {
            if let Some(x) = self.by_public.get(&public.to_vec()) {
                Some(x.clone())
            } else {
                None
            }
        };

        if let Some(item) = res {
            self.get_by_pointer(item.clone())
        } else {
            None
        }
    }

    fn get_by_pointer_unchecked(&mut self, pointer: usize) -> Option<MutexConnectionInfo> {
        if let Some(info) = self.map.get(&pointer) {
            Some(info.clone())
        } else {
            None
        }
    }

    fn get_by_pointer(&mut self, pointer: usize) -> Option<MutexConnectionInfo> {
        let info = self.get_by_pointer_unchecked(pointer);

        if let Some(info) = info {
            use_item!(info.0, connection => {
                if connection.is_expired() {
                    self.remove_connection_by_pointer(pointer);

                    None
                } else {
                    Some(info)
                }
            })
        } else {
            None
        }
    }

    fn remove_connection_by_pointer(&mut self, pointer: usize) {
        if let Some(info) = self.map.remove(&pointer) {
            self.remove_connection(info);
        }
    }

    fn remove_connection(&mut self, connection: MutexConnectionInfo) {
        use_item!(connection.0, connection => {
            self.by_addr.remove(&connection.addr);

            if let &Some(ref key) = &connection.public_key {
                self.by_public.remove(&key.to_vec());
            }
        });
    }

    fn link(&mut self, addr: SocketAddr, public: Bytes) {
        if let Some(index) = self.by_addr.get(&addr) {
            self.by_public.insert(public.to_vec(), index.clone());
        }
    }

    pub fn iter(&self) -> Values<usize, MutexConnectionInfo> {
        self.map.values()
    }
}

pub struct Server<R>
    where R: Router<R> {
    queue: Vec<ServerEvent>,
    closed: bool,
    pub connections: ConnectionCollection,
    pub config: Config,
    router: Arc<Mutex<R>>,
}

impl Server<DumbRouter> {
    pub fn new(config: Config) -> Server<DumbRouter> {
        Server::new_with_router(config, DumbRouter::new())
    }
}

impl<R> Server<R>
    where R: Router<R> {

    pub fn new_with_router(config: Config, router: R) -> Server<R> {
        Server {
            queue: vec![],
            closed: false,
            connections: ConnectionCollection::new(),
            config,
            router: Arc::new(Mutex::new(router)),
        }
    }

    fn queue_event(&mut self, event: ServerEvent) {
        self.queue.push(event)
    }

    fn on_tunnel(&mut self, data: Bytes) {
        use_item!(self.router, mut router => router.handle_packet(data));
    }

    fn on_dht_krpc(&self, data: Bytes, addr: SocketAddr) {
        // TODO
    }

    fn handle_message(&mut self, message: Message, connection_info: MutexConnectionInfo) {
        {
            let info = connection_info.get_mutex();
            debug_println!("Message received: {:?} from {:?}", message, info.addr);
        }

        if message.message_type == MessageType::Ethernet {
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

        info.public_key = Some(key_exchange.public_key.clone());

        self.connections.link(info.addr.clone(), key_exchange.public_key.clone());

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

    fn get_connection_info(&mut self, addr: SocketAddr) -> MutexConnectionInfo {
        if let Some(connection_info) = self.connections.get_by_addr(addr.clone()) {
            return connection_info.clone();
        }

        self.connections.add(ConnectionInfo::new(addr))
    }

    fn on_packet(&mut self, data: Bytes, addr: SocketAddr) {
        match Packet::from_bytes(data) {
            Some(Packet::MainlineDHT(data)) => {
                self.on_dht_krpc(data, addr);
            }

            Some(Packet::KeyExchange(key_exchange)) => {
                let info = self.get_connection_info(addr);
                self.handle_key_exchange(key_exchange, info );
            }

            Some(Packet::EncryptedMessage(encrypted_message)) => {
                let info = self.get_connection_info(addr);
                self.on_message(encrypted_message, info);
            }

            _ => {}
        }
    }

    fn on_event(&mut self, event: ServerEvent) {
        debug_println!("Got event: {:?}", event);

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
            if let Some(connection) = self.connections.get_by_addr(addr.clone()) {
                if connection.get_mutex().connection_state.is_null() {
                    return;
                }
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

            self.connections.add(info);
        }
    }
}

impl<R> Stream for Server<R>
    where R: Router<R> {
    type Item = ServerEvent;
    type Error = Error;

    fn poll(&mut self) -> Result<Async<Option<<Self as Stream>::Item>>, <Self as Stream>::Error> {
        if self.queue.len() == 0 {
            return Ok(Async::NotReady);
        }

        Ok(Async::Ready(Some(self.queue.remove(0))))
    }
}

impl<R> Sink for Server<R>
    where R: Router<R> {
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