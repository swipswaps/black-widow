use std::net::SocketAddr;
use std::mem;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::u64;
use std::sync::{Mutex, Arc};
use std::sync::mpsc::{channel, Sender};
use std::time::Instant;
use std::collections::HashMap;
use std::collections::hash_map::Values;

use bytes::{Bytes, ByteOrder};
use byteorder::BigEndian;
use ring::agreement::EphemeralPrivateKey;
use ring::rand::{SecureRandom, SystemRandom};

use super::prelude::*;

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
        self.last_update = Instant::now();
    }

    pub fn next_packet_id(&mut self) -> u64 {
        if self.packet_id == 0 {
            let mut x = vec![0u8; 8];
            SystemRandom::new().fill(&mut x).unwrap();

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
pub struct MutexConnectionInfo(Arc<Mutex<ConnectionInfo>>, SocketAddr, Option<Bytes>);

impl MutexConnectionInfo {
    pub fn new(addr: SocketAddr) -> MutexConnectionInfo {
        let info = ConnectionInfo::new(addr);

        MutexConnectionInfo::wrap(info)
    }

    pub fn wrap(info: ConnectionInfo) -> MutexConnectionInfo {
        let addr = info.addr.clone();
        let public_key = info.public_key.clone();

        MutexConnectionInfo(Arc::new(Mutex::new(info)), addr, public_key)
    }

    #[inline]
    pub fn use_info<T, F: FnOnce(&mut ConnectionInfo) -> T>(&self, cb: F) -> T {
        let res = use_item!(self.0, mut conn => cb(&mut conn));

        res
    }

    pub fn addr(&self) -> SocketAddr {
        self.1.clone()
    }

    pub fn public_key(&self) -> Option<Bytes> { self.2.clone() }

    pub fn bump(&self) {
        self.use_info(|info| info.bump());
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

    fn get_by_pointer(&mut self, pointer: usize) -> Option<MutexConnectionInfo> {
        if let Some(info) = self.map.get(&pointer) {
            Some(info.clone())
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

            if let Some(ref mut mutex) = self.map.get_mut(index) {
                mutex.2 = Some(public.clone());
            }
        }
    }

    pub fn iter(&self) -> Values<usize, MutexConnectionInfo> {
        self.map.values()
    }

    pub fn get_cloned(&mut self) -> Vec<MutexConnectionInfo> {
        self.map.values().cloned().collect()
    }
}

#[cfg(feature = "python-router")]
#[derive(Clone)]
pub enum RouterUnawareServer {
    PythonRouter(Server<PythonRouter>),
    DumbRouter(Server<DumbRouter>),
}

#[cfg(not(feature = "python-router"))]
#[derive(Clone)]
pub enum RouterUnawareServer {
    DumbRouter(Server<DumbRouter>),
}

#[cfg(feature = "python-router")]
macro_rules! router_unaware_action {
    ($on:ident, $name:tt => $action:expr) => {
        match $on {
            RouterUnawareServer::PythonRouter($name) => {
                $action
            },

            RouterUnawareServer::DumbRouter($name) => {
                $action
            },
        }
    };
}

#[cfg(not(feature = "python-router"))]
macro_rules! router_unaware_action {
    ($on:ident, $name:tt => $action:expr) => {
        match $on {
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
            RouterChoice::Dumb => {
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
    fn connect(&self, addr: SocketAddr) {
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

    fn send_event(&self, event: ServerEvent) {
        router_unaware_action!(self, router => {
            router.send_event(event);
        })
    }

    fn set_sender(&mut self, sender: Sender<ServerEvent>) {
        router_unaware_action!( self, router => {
            router.set_sender(sender);
        });
    }
}

#[derive(Clone)]
pub struct Server<R>
    where R: Router<R> + Clone {
    interface_name: String,
    pub connections: Arc<Mutex<ConnectionCollection>>,
    pub config: Config,
    router: R,
    sender: Sender<ServerEvent>,
}

#[derive(Clone)]
pub struct ServerRemote {
    pub connections: Arc<Mutex<ConnectionCollection>>,
    sender: Sender<ServerEvent>,
}

impl ServerRemote {
    fn get_connections(&self) -> Vec<MutexConnectionInfo> {
        use_item!(self.connections, mut connections => connections.get_cloned())
    }

    pub fn write_packet(&self, data: Bytes) {
        self.sender.send(ServerEvent::Tunnel(data)).unwrap();
    }

    pub fn send_message(&self, message: &Message, info: MutexConnectionInfo) {
        let (paramaters, packet_id, addr) = info.use_info(|mutex| (mutex.connection_state.get_parameters(), mutex.next_packet_id(), mutex.addr.clone()));
        if let Some(parameters) = paramaters {
            let next_id = packet_id;
            let encrypted_message = EncryptedMessage::new_from_message(next_id, &message, &parameters);

            if let Some(bytes) = Packet::EncryptedMessage(encrypted_message).get_bytes() {
                self.sender.send(ServerEvent::Packet(bytes, addr)).unwrap();
            }
        }
    }

    pub fn publish_message(&self, message: Message) {
        for conn in self.get_connections() {
            self.send_message(&message, conn);
        }
    }

    pub fn send_message_to_addr(&self, message: Message, addr: SocketAddr) {
        if let Some(info) = use_item!(self.connections, mut connections => connections.get_by_addr(addr.clone())) {
            self.send_message(&message, info);
        }
    }

    pub fn send_message_to_client(&self, message: Message, id: Bytes) {
        if let Some(info) = use_item!(self.connections, mut connections => connections.get_by_public_key(id.clone())) {
            self.send_message(&message, info);
        }
    }
}

pub trait ServerLike {
    fn connect(&self, addr: SocketAddr);
    fn ready(&mut self) {}
    fn set_interface_name(&mut self, interface_name: String);
    fn set_sender(&mut self, sender: Sender<ServerEvent>);
    fn send_event(&self, event: ServerEvent);
}

impl Server<DumbRouter> {
    pub fn new(config: Config) -> Server<DumbRouter> {
        Server::new_with_router(config, DumbRouter::new())
    }
}

impl<R> Server<R>
    where R: Router<R> + 'static + Clone {
    pub fn new_with_router(config: Config, mut router: R) -> Server<R> {
        router.start();

        let (sender, _) = channel();

        Server {
            connections: Arc::new(Mutex::new(ConnectionCollection::new())),
            config,
            interface_name: String::new(),
            router: router,
            sender,
        }
    }

    pub fn get_interface_name(&self) -> String {
        self.interface_name.clone()
    }

    fn queue_event(&self, event: ServerEvent) {
        self.sender.send(event).unwrap();
    }

    #[allow(dead_code)]
    fn get_connections(&self) -> Vec<MutexConnectionInfo> {
        use_item!(self.connections, mut connections => connections.get_cloned())
    }

    fn on_tunnel(&self, data: Bytes) {
        self.router.handle_packet(data);
    }

    fn on_dht_krpc(&self, _data: Bytes, _addr: SocketAddr) {
        // TODO
    }

    fn handle_message(&self, message: Message, connection_info: MutexConnectionInfo) {
        self.router.handle_message(message, connection_info.addr(), connection_info.public_key().unwrap());
    }

    fn on_message(&self, encrypted_message: EncryptedMessage, connection_info: MutexConnectionInfo) {
        let para = connection_info.use_info(|info| info.connection_state.get_parameters());
        let message = {
            if let Some(ref para) = para {
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
        };

        if message.is_none() {
            return;
        }

        let message = message.unwrap();
        self.handle_message(message, connection_info);
    }

    fn handle_key_exchange(&self, key_exchange: KeyExchange, connection_info: MutexConnectionInfo) {
        if !key_exchange.verify(&self.config) {
            return;
        }

        connection_info.use_info(|info| {
            info.bump();

            let state = mem::replace(&mut info.connection_state, ConnectionState::Null);

            info.public_key = Some(key_exchange.public_key.clone());

            use_item!(self.connections, mut connections => connections.link(info.addr.clone(), key_exchange.public_key.clone()));

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
                            info.connection_state = ConnectionState::Stream(parameters);

                            self.router.handle_new_client(info.addr.clone(), info.public_key.clone().unwrap());
                        }
                    }
                }

                ConnectionState::Stream(_) => {
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

                                self.router.handle_new_client(info.addr.clone(), info.public_key.clone().unwrap())
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

    fn get_connection_info(&self, addr: SocketAddr) -> MutexConnectionInfo {
        use_item!(self.connections, mut connections => {
            if let Some(connection_info) = connections.get_by_addr(addr.clone()) {
                connection_info.clone()
            } else {
                connections.add(ConnectionInfo::new(addr))
            }
        })
    }

    fn on_packet(&self, data: Bytes, addr: SocketAddr) {
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

    fn on_event(&self, event: ServerEvent) {
        debug_println!("Got event: {:?}", event);

        match event {
            ServerEvent::Tunnel(data) => self.on_tunnel(data),
            ServerEvent::Packet(data, addr) => self.on_packet(data, addr),
            ServerEvent::Control(data) => self.on_control(data),
        }
    }

    fn on_control(&self, data: String) {
        if data.starts_with("connect ") {
            let try = data[8..].trim();

            if let Ok(x) = try.parse::<SocketAddr>() {
                self.connect(x);
                self.queue_event(ServerEvent::Control(String::from("Ok")));
            } else {
                self.queue_event(ServerEvent::Control(String::from("Not a valid IP")));
            }

            return;
        }

        self.queue_event(ServerEvent::Control(String::from("Invalid input")))
    }
}

impl<R> ServerLike for Server<R>
    where R: Router<R> + 'static + Clone {
    fn connect(&self, addr: SocketAddr) {
        {
            if let Some(connection) = use_item!(self.connections, mut connections => connections.get_by_addr(addr.clone())) {
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

            use_item!(self.connections, mut connections => connections.add(info));
        }
    }

    fn ready(&mut self) {
        self.router.ready(ServerRemote {
            sender: self.sender.clone(),
            connections: self.connections.clone(),
        }, Bytes::from(self.config.key.get_value().unwrap()));
    }

    fn set_interface_name(&mut self, interface_name: String) {
        self.router.set_interface_name(interface_name.clone());
        self.interface_name = interface_name;
    }

    fn send_event(&self, event: ServerEvent) {
        self.on_event(event)
    }

    fn set_sender(&mut self, sender: Sender<ServerEvent>) {
        self.sender = sender;
    }
}