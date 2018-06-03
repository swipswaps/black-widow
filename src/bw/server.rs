use std::net::SocketAddr;
use std::io::Error;
use std::mem;
use std::fmt;
use std::fmt::{Debug, Formatter};
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

#[macro_use]
use super::macros;

#[derive(Debug, Clone)]
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

impl Debug for ConnectionState {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            ConnectionState::Null => write!(f, "ConnectionState::Null"),
            ConnectionState::KeyExchange(_) => write!(f, "ConnectionState::KeyExchange(...)"),
            ConnectionState::Stream(x) => write!(f, "ConnectionState::Stream({:?})", x),
        }
    }
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

    pub fn get_parameters(&self) -> Option<EncryptionParameters> {
        if let &ConnectionState::Stream(ref params) = self {
            Some(params.clone())
        } else {
            None
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
        // self.last_update = Instant::now();
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
        false
        // Instant::now().duration_since(self.last_update).as_secs() > 60
    }
}

#[derive(Clone)]
pub struct MutexConnectionInfo(Arc<Mutex<ConnectionInfo>>, SocketAddr);

impl MutexConnectionInfo {
    pub fn new(addr: SocketAddr) -> MutexConnectionInfo {
        let info = ConnectionInfo::new(addr);

        MutexConnectionInfo::wrap(info)
    }

    pub fn wrap(info: ConnectionInfo) -> MutexConnectionInfo {
        let addr = info.addr.clone();

        MutexConnectionInfo(Arc::new(Mutex::new(info)), addr)
    }

    #[inline]
    pub fn use_info<T, F: FnOnce(&mut ConnectionInfo) -> T>(&self, cb: F) -> T {
        debug_println!("ConnectionInfo({:?}): Open", self.1);
        let res = use_item!(self.0, mut conn => cb(&mut conn));
        debug_println!("ConnectionInfo({:?}): Close", self.1);

        res
    }

    pub fn addr(&self) -> SocketAddr {
        self.1.clone()
    }

    pub fn bump(&self) {
        // self.use_info(|info| info.bump());
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
        self.pointer += 1;

        let info = MutexConnectionInfo::wrap(info);

        let clone = info.clone();

        self.map.insert(index, info);

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

        clone
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
        let mut should_remove = false;

        if let Some(info) = info {
            if info.use_info(|x| x.is_expired()) {
                self.remove_connection_by_pointer(pointer);
                None
            } else {
                Some(info)
            }
        } else {
            return None;
        }
    }

    fn remove_connection_by_pointer(&mut self, pointer: usize) {
        if let Some(info) = self.map.remove(&pointer) {
            self.remove_connection(info);
        }
    }

    fn remove_connection(&mut self, connection: MutexConnectionInfo) {
        connection.use_info(|connection| {
            self.by_addr.remove(&connection.addr);

            if let &Some(ref key) = &connection.public_key {
                self.by_public.remove(&key.to_vec());
            }
        })
    }

    fn link(&mut self, addr: SocketAddr, public: Bytes) {
        if let Some(index) = self.by_addr.get(&addr) {
            self.by_public.insert(public.to_vec(), index.clone());
        }
    }

    pub fn iter(&self) -> Values<usize, MutexConnectionInfo> {
        self.map.values()
    }

    pub fn get_valid(&mut self) -> Vec<MutexConnectionInfo> {
        let (expired, valid) = self.map.values().cloned().partition(|x| x.use_info(|x| x.is_expired()));

        for expire in expired {
            self.remove_connection(expire);
        }

        return valid;
    }
}

pub enum RouterUnawareServer {
    #[cfg(feature = "python-router")]
    PythonRouter(Server<PythonRouter>),
    DumbRouter(Server<DumbRouter>),
}

macro_rules! router_unaware_action {
    ($on:ident, $name:tt => $action:expr) => {
        match $on {
            RouterUnawareServer::PythonRouter($name) => {
                $action
            },

            #[cfg(feature = "python-router")]
            RouterUnawareServer::DumbRouter($name) => {
                $action
            },
        }
    };
}

impl RouterUnawareServer {
    pub fn new(config: Config) -> RouterUnawareServer {
        let router = config.router.name.clone();

        match router {
            ChosenRouter::Dumb => {
                RouterUnawareServer::DumbRouter(Server::new(config))
            }

            #[cfg(feature = "python-router")]
            ChosenRouter::Python => {
                let script = config.router.python.clone().unwrap().script.clone();

                RouterUnawareServer::PythonRouter(Server::new_with_router(
                    config,
                    PythonRouter::new(script),
                ))
            }
        }
    }
}

impl ServerLike for RouterUnawareServer {
    fn connect(&mut self, addr: SocketAddr) {
        router_unaware_action!(self, router => {
            router.connect(addr);
        })
    }

    fn ready(&mut self) {
        router_unaware_action!(self, r => r.ready())
    }

    fn set_interface_name(&mut self, interface_name: String) {
        router_unaware_action!(self, router => {
            router.set_interface_name(interface_name);
        })
    }

    fn send_event(&mut self, event: ServerEvent) {
        router_unaware_action!(self, router => {
            router.send_event(event);
        })
    }

    fn flush_queue(&mut self) -> Vec<ServerEvent> {
        router_unaware_action!(self, router => {
            router.flush_queue()
        })
    }

    fn set_event_callback<F>(&mut self, callback: F) -> ()
        where F: Fn(ServerEvent) -> () + 'static {
        router_unaware_action!( self, router => {
            router.set_event_callback(callback);
        });
    }
}

impl Stream for RouterUnawareServer {
    type Item = ServerEvent;
    type Error = Error;

    fn poll(&mut self) -> Result<Async<Option<<Self as Stream>::Item>>, <Self as Stream>::Error> {
        router_unaware_action!(self, router => router.poll())
    }
}

impl Sink for RouterUnawareServer {
    type SinkItem = ServerEvent;
    type SinkError = Error;

    fn start_send(&mut self, item: <Self as Sink>::SinkItem) -> Result<AsyncSink<<Self as Sink>::SinkItem>, <Self as Sink>::SinkError> {
        router_unaware_action!(self, router => router.start_send(item))
    }

    fn poll_complete(&mut self) -> Result<Async<()>, <Self as Sink>::SinkError> {
        router_unaware_action!(self, router => router.poll_complete())
    }

    fn close(&mut self) -> Result<Async<()>, <Self as Sink>::SinkError> {
        router_unaware_action!(self, router => router.close())
    }
}

pub struct Server<R>
    where R: Router<R> {
    queue: Vec<ServerEvent>,
    interface_name: String,
    closed: bool,
    pub connections: ConnectionCollection,
    pub config: Config,
    router: Arc<Mutex<R>>,
    callback: Option<Box<Fn(ServerEvent) -> ()>>,
}

pub trait ServerLike {
    fn connect(&mut self, addr: SocketAddr);
    fn ready(&mut self) {}
    fn set_interface_name(&mut self, interface_name: String);
    fn set_event_callback<F>(&mut self, callback: F) -> ()
        where F: Fn(ServerEvent) -> () + 'static;
    fn send_event(&mut self, event: ServerEvent);
    fn flush_queue(&mut self) -> Vec<ServerEvent>;
}

impl Server<DumbRouter> {
    pub fn new(config: Config) -> Server<DumbRouter> {
        Server::new_with_router(config, DumbRouter::new())
    }
}

impl<R> Server<R>
    where R: Router<R> + 'static {
    pub fn new_with_router(config: Config, mut router: R) -> Server<R> {
        router.start();

        Server {
            queue: vec![],
            closed: false,
            connections: ConnectionCollection::new(),
            config,
            interface_name: String::new(),
            router: Arc::new(Mutex::new(router)),
            callback: None,
        }
    }

    pub fn get_interface_name(&self) -> String {
        self.interface_name.clone()
    }

    fn queue_event(&mut self, event: ServerEvent) {
        if let Some(ref cb) = self.callback {
            (cb)(event);
            return;
        }

        self.queue.push(event);
        self.check_callback();
    }

    fn check_callback(&mut self) {
        if self.callback.is_some() {
            self.check_queue();

            let events = self.flush_queue();

            if let Some(ref cb) = self.callback {
                for event in events {
                    cb(event);
                }
            }
        };
    }

    fn check_queue(&mut self) -> bool {
        let router_events = use_item!(self.router, mut r => {
            if r.has_queue() {
                r.flush_queue()
            } else {
                vec![]
            }
        });

        if router_events.len() > 0 {
            self.queue_router_events(router_events);
        }

        self.queue.len() > 0
    }

    fn queue_router_events(&mut self, events: Vec<RouterEvent>) {
        let mut server_events = vec![];

        for event in events {
            match event {
                RouterEvent::PublishMessage(message) => {
                    for conn in self.connections.iter() {
                        conn.use_info(|mutex| {
                            if let Some(parameters) = mutex.connection_state.get_parameters() {
                                let next_id = mutex.next_packet_id();
                                let encrypted_message = EncryptedMessage::new_from_message(next_id, &message, &parameters);

                                if let Some(bytes) = Packet::EncryptedMessage(encrypted_message).get_bytes() {
                                    server_events.push(ServerEvent::Packet(bytes, mutex.addr.clone()));
                                }
                            }
                        });
                    }
                }

                RouterEvent::Packet(payload) => {
                    server_events.push(ServerEvent::Tunnel(payload));
                }

                RouterEvent::SendMessageToAddr(message, addr) => {
                    if let Some(conn) = self.connections.get_by_addr(addr.clone()) {
                        conn.use_info(|info| {
                            if let Some(parameters) = info.connection_state.get_parameters() {
                                let next_id = info.next_packet_id();

                                let encrypted_message = EncryptedMessage::new_from_message(next_id, &message, &parameters);

                                if let Some(bytes) = Packet::EncryptedMessage(encrypted_message).get_bytes() {
                                    server_events.push(ServerEvent::Packet(bytes, addr));
                                }
                            }
                        });
                    }
                }

                RouterEvent::SendMessageToClient(message, id) => {
                    if let Some(conn) = self.connections.get_by_public_key(Bytes::from(id)) {
                        let addr = conn.addr();

                        conn.use_info(|info| {
                            if let Some(parameters) = info.connection_state.get_parameters() {
                                let next_id = info.next_packet_id();
                                let encrypted_message = EncryptedMessage::new_from_message(next_id, &message, &parameters);

                                if let Some(bytes) = Packet::EncryptedMessage(encrypted_message).get_bytes() {
                                    server_events.push(ServerEvent::Packet(bytes, addr));
                                }
                            }
                        });
                    }
                }

                _ => {}
            }
        }

        self.queue.extend(server_events);
    }

    fn on_tunnel(&mut self, data: Bytes) {
        let message = Message::new(MessageType::Ethernet, data);
        // use_item!(self.router, mut router => router.handle_packet(data));
        // self.check_callback();
        if let Some(cb) = mem::replace(&mut self.callback, None) {
            for conn in self.connections.iter() {
                conn.use_info(|mutex| {
                    if let Some(parameters) = mutex.connection_state.get_parameters() {
                        let next_id = mutex.next_packet_id();
                        let encrypted_message = EncryptedMessage::new_from_message(next_id, &message, &parameters);

                        if let Some(bytes) = Packet::EncryptedMessage(encrypted_message).get_bytes() {
                            (cb)(ServerEvent::Packet(bytes, mutex.addr.clone()));
                        }
                    }
                });
            }

            self.callback = Some(cb);
        }
    }

    fn on_dht_krpc(&self, data: Bytes, addr: SocketAddr) {
        // TODO
    }

    fn handle_message(&mut self, message: Message, connection_info: MutexConnectionInfo) {
        debug_println!("Message received: {:?} from {:?}", message, connection_info.addr());

        if message.message_type == MessageType::Ethernet {
            self.queue_event(ServerEvent::Tunnel(message.payload));
        }
    }

    fn on_message(&mut self, encrypted_message: EncryptedMessage, connection_info: MutexConnectionInfo) {
        let message = {
            connection_info.use_info(|info| {
                if let ConnectionState::Stream(ref para) = info.connection_state {
                    if let Some(message) = encrypted_message.decrypt(para) {
                        if message.verify(para) {
                            Some(message)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
        };

        if message.is_none() {
            return;
        }

        let message = message.unwrap();
        self.handle_message(message, connection_info);
    }

    fn handle_key_exchange(&mut self, key_exchange: KeyExchange, connection_info: MutexConnectionInfo) {
        if !key_exchange.verify(&self.config) {
            return;
        }

        connection_info.use_info(|info| {
            info.bump();

            let state = mem::replace(&mut info.connection_state, ConnectionState::Null);

            info.public_key = Some(key_exchange.public_key.clone());

            self.connections.link(info.addr.clone(), key_exchange.public_key.clone());

            debug_println!("Connection state: {:?} from: {:?}", state, info.addr.clone());

            match state {
                ConnectionState::KeyExchange(key) => {
                    match key_exchange.derive_encryption_parameters(key, &self.config) {
                        None => {
                            println!("Failed connecting to {:?}", info.addr);
                            info.connection_state = ConnectionState::Null;
                        }

                        Some(parameters) => {
                            println!("Setup connection with {:?}", info.addr);
                            info.connection_state = ConnectionState::Stream(parameters)
                        }
                    }
                }

                ConnectionState::Stream(x) => {
                    if let Ok((exchange, key)) = KeyExchange::new_key_exchange(&self.config) {
                        if let Some(bytes) = Packet::KeyExchange(exchange).get_bytes() {
                            info.connection_state = ConnectionState::KeyExchange(key);
                            self.queue_event(ServerEvent::Packet(bytes, info.addr.clone()));
                        } else {
                            info.connection_state = ConnectionState::Null;
                        }
                    } else {
                        info.connection_state = ConnectionState::Null;
                    }
                }

                ConnectionState::Null => {
                    println!("New connection from {:?}", info.addr);

                    if let Ok((exchange, key)) = KeyExchange::new_key_exchange(&self.config) {
                        if let Some(parameters) = key_exchange.derive_encryption_parameters(key, &self.config) {
                            if let Some(bytes) = Packet::KeyExchange(exchange).get_bytes() {
                                println!("Connection established with {:?}", info.addr);
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
        });
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
                self.handle_key_exchange(key_exchange, info);
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
                self.queue_event(ServerEvent::Control(String::from("Ok")));
            } else {
                self.queue_event(ServerEvent::Control(String::from("Not a valid IP")));
            }
        }
    }
}

impl<R> ServerLike for Server<R>
    where R: Router<R> + 'static {
    fn connect(&mut self, addr: SocketAddr) {
        {
            if let Some(connection) = self.connections.get_by_addr(addr.clone()) {
                if !connection.use_info(|info| info.connection_state.is_null()) {
                    println!("Already connected with {:?}", addr);
                    return;
                }
            }
        }

        println!("Trying to establish a connection with {:?}", addr);

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

    fn ready(&mut self) {
        use_item!( self.router, mut r => r.ready())
    }

    fn set_interface_name(&mut self, interface_name: String) {
        use_item!( self.router, mut router => router.set_interface_name(interface_name.clone()));
        self.interface_name = interface_name;
    }

    fn send_event(&mut self, event: ServerEvent) {
        self.on_event(event)
    }

    fn flush_queue(&mut self) -> Vec<ServerEvent> {
        self.check_queue();

        mem::replace(&mut self.queue, vec![])
    }

    fn set_event_callback<F>(&mut self, callback: F) -> ()
        where F: Fn(ServerEvent) -> () + 'static {
        self.callback = Some(Box::new(callback));
    }
}

impl<R> Stream for Server<R>
    where R: Router<R> + 'static {
    type Item = ServerEvent;
    type Error = Error;

    fn poll(&mut self) -> Result<Async<Option<<Self as Stream>::Item>>, <Self as Stream>::Error> {
        if !self.check_queue() {
            return Ok(Async::NotReady);
        }

        Ok(Async::Ready(Some(self.queue.remove(0))))
    }
}

impl<R> Sink for Server<R>
    where R: Router<R> + 'static {
    type SinkItem = ServerEvent;
    type SinkError = Error;

    fn start_send(&mut self, item: <Self as Sink>::SinkItem) -> Result<AsyncSink<<Self as Sink>::SinkItem>, <Self as Sink>::SinkError> {
        if self.closed {
            return Ok(AsyncSink::NotReady(item));
        }

        debug_println!("Start on_event");
        self.on_event(item);
        debug_println!("End on_event");

        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Result<Async<()>, <Self as Sink>::SinkError> {
        if self.closed {
            Ok(Async::NotReady)
        } else {
            Ok(Async::Ready(()))
        }
    }

    fn close(&mut self) -> Result<Async<()>, <Self as Sink>::SinkError> {
        self.closed = true;

        Ok(Async::Ready(()))
    }
}