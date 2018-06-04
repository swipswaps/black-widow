use std::fs::File;
use std::io::prelude::*;
use std::io;
use std::ascii::AsciiExt;

use std::fmt::{Debug, Formatter};
use std::fmt;

use bytes::Bytes;
use toml::value::{Value, Table};
use uuid::Uuid;

use untrusted::Input;

use tun_tap::Mode;

use ring::digest;
use ring::hmac::SigningKey;
use ring::signature::{Ed25519KeyPair, ED25519};


fn read_file(file_path: &str, path: &str) -> Result<Bytes, Vec<String>> {
    let mut error_vec = vec![];

    let file = File::open(file_path);

    if file.is_err() {
        error_vec.push(String::from(format!("Couldn't open file '{}' for {}", file_path, path)));

        return Err(error_vec);
    }

    let mut file = file.unwrap();
    let mut data: Vec<u8> = vec![0; 1024];
    let size = file.read(&mut data);

    if size.is_err() {
        error_vec.push(String::from(format!("Couldn't open file '{}' for {}", file_path, path)));

        return Err(error_vec);
    }

    let size = size.unwrap();

    Ok(Bytes::from(&data[..size]))
}

fn parse_file_or_value(value: &Value, path: &str, default_is_path: bool) -> Result<Bytes, Vec<String>> {
    let mut error_vec = vec![];

    match value {
        &Value::String(ref string) => {
            if default_is_path {
                return read_file(&string, path);
            } else {
                return Ok(Bytes::from(string.as_bytes()));
            }
        }

        &Value::Table(ref table) => {
            if let Some(&Value::String(ref value)) = table.get("value") {
                return Ok(Bytes::from(value.as_bytes()));
            }

            if let Some(&Value::String(ref file)) = table.get("file") {
                return read_file(&file, path);
            }

            error_vec.push(String::from(format!("Need a string with the key 'value' or 'file' in {}", path)));
        }

        _ => {
            error_vec.push(String::from(format!("Need a string or table with the key 'value' or 'file' for {}", path)));
        }
    }

    Err(error_vec)
}

#[derive(Debug, Clone)]
pub enum Auth {
    SharedSecret(SharedSecret),
    Authority(Authority),
}

impl Auth {
    pub fn from_value(value: &Value) -> Result<Auth, Vec<String>> {
        let mut error_vec: Vec<String> = vec![];

        match value {
            &Value::String(ref string) => {
                return Ok(Auth::SharedSecret(SharedSecret::new(Bytes::from(string.as_bytes()))));
            }

            &Value::Table(ref table) => {
                if let Some(secret) = table.get("secret") {
                    match parse_file_or_value(secret, "auth.secret", false) {
                        Err(err) => {
                            return Err(err);
                        }

                        Ok(bytes) => {
                            return Ok(Auth::SharedSecret(SharedSecret::new(bytes)));
                        }
                    }
                }

                if table.contains_key("key") && table.contains_key("signature") {
                    let key_result = parse_file_or_value(&table["key"], "auth.key", true);
                    let signature_result = parse_file_or_value(&table["signature"], "auth.signature", true);

                    if let &Err(ref errors) = &key_result {
                        error_vec.extend({
                            let mut new_errors = vec![];
                            for error in errors {
                                new_errors.push(String::from(error.as_str()));
                            }

                            new_errors
                        });
                    }

                    if let &Err(ref errors) = &signature_result {
                        error_vec.extend({
                            let mut new_errors = vec![];
                            for error in errors {
                                new_errors.push(String::from(error.as_str()));
                            }

                            new_errors
                        });
                    }

                    if let (Ok(key), Ok(signature)) = (key_result, signature_result) {
                        return Ok(Auth::Authority(Authority {
                            key,
                            signature,
                        }));
                    }
                }
            }

            _ => {}
        }

        error_vec.push(String::from("'auth' key expects an string, or table with the key 'secret' or keys 'signature' and 'key'"));

        Err(error_vec)
    }

    pub fn is_authority(&self) -> bool {
        if let &Auth::Authority(_) = self {
            return true;
        }

        false
    }

    pub fn is_shared_secret(&self) -> bool {
        if let &Auth::SharedSecret(_) = self {
            return true;
        }

        false
    }
}



#[derive(Debug, Clone)]
pub struct Authority {
    pub key: Bytes,
    pub signature: Bytes,
}

#[derive(Clone)]
pub struct SharedSecret {
    pub secret: Bytes,
}

impl Debug for SharedSecret {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "SharedSecret {{ secret: {:?} }}", self.secret)
    }
}

impl SharedSecret {
    pub fn get_signing_key(&self) -> SigningKey {
        SigningKey::new(&digest::SHA512, &self.secret)
    }

    pub fn new(secret: Bytes) -> SharedSecret {
        SharedSecret {
            secret,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub enum ChosenRouter {
    Dumb,
    #[cfg(feature = "python-router")]
    Python,
}

static MAP: &'static [(&'static str, ChosenRouter)] = &[
    ("dumb", ChosenRouter::Dumb),
        #[cfg(feature = "python-router")]
    ("python", ChosenRouter::Python),
];

impl ChosenRouter {
    fn get_map() -> &'static [(&'static str, ChosenRouter)] {
        &MAP
    }

    fn as_str(&self) -> &'static str {
        for (name, token) in ChosenRouter::get_map() {
            if *token == *self {
                return *name;
            }
        }

        "dumb"
    }

    fn from_str(s: String) -> Option<Self> {
        for (name, token) in ChosenRouter::get_map() {
            if *name == s {
                return Some(*token);
            }
        }

        None
    }
}

#[derive(Debug, Clone)]
pub struct Interface {
    pub name: String,
    pub mode: Mode,
    pub mtu: u16,
}

impl Interface {
    pub fn from_value(value: &Value) -> Result<Interface, Vec<String>> {
        if let &Value::Table(ref table) = value {
            let mut name = String::from("bw%d");
            let mut mode = Mode::Tun;
            let mut mtu = 1400;

            if let Some(&Value::String(ref config_name)) = table.get("name") {
                name = config_name.clone();
            }

            if let Some(&Value::String(ref config_mode)) = table.get("mode") {
                let config_mode = config_mode.clone();

                match config_mode.as_str() {
                    "tun" => {
                        mode = Mode::Tun;
                    }

                    "tap" => {
                        mode = Mode::Tap;
                    }

                    x => {
                        return Err(vec![format!("interface.mode should be 'tun' or 'tap'; '{}' given", x)])
                    }
                }
            }

            if let Some(&Value::Integer(ref number)) = table.get("mtu") {
                if *number > 65535 || *number <= 0 {
                    return Err(vec![format!("interface.mtu should be between 0 and 65535; '{}' given", *number)])
                }

                mtu = *number as u16;
            }

            Ok(Interface {
                mtu,
                name,
                mode
            })
        } else {
            Err(vec!["interface should be a table with the keys name, mode and mtu".to_string()])
        }
    }
}

#[derive(Debug, Clone)]
pub struct RouterConfig {
    pub name: ChosenRouter,
    #[cfg(feature = "python-router")]
    pub python: Option<PythonRouterConfig>,
}

impl RouterConfig {
    pub fn from_value(value: &Value) -> Result<RouterConfig, Vec<String>> {
        if let &Value::Table(ref table) = value {
            if let Some(&Value::String(ref name)) = table.get("name") {
                if let Some(token) = ChosenRouter::from_str(name.clone()) {
                    return match token {
                        ChosenRouter::Dumb => {
                            Ok(RouterConfig {
                                name: ChosenRouter::Dumb,
                                #[cfg(feature = "python-router")]
                                python: None,
                            })
                        }

                        #[cfg(feature = "python-router")]
                        ChosenRouter::Python => {
                            return Ok(RouterConfig {
                                name: ChosenRouter::Python,
                                python: Some(PythonRouterConfig::from_value(table.get("python").unwrap_or_else(|| &Value::Boolean(false)))?),
                            });
                        }
                    };
                } else {
                    return Err(vec![format!("router.name should be one of: {}", ChosenRouter::get_map().iter().fold("".to_string(), |acc, x| {
                        if acc.len() == 0 {
                            x.1.as_str().to_string()
                        } else {
                            format!("{}, {}", acc, x.1.as_str().to_string())
                        }
                    }))]);
                }
            }
        }

        Err(vec!["router should be a table with the key 'name'".to_string()])
    }
}

#[cfg(feature = "python-router")]
#[derive(Debug, Clone)]
pub struct PythonRouterConfig {
    pub script: String
}

#[cfg(feature = "python-router")]
impl PythonRouterConfig {
    pub fn from_value(value: &Value) -> Result<PythonRouterConfig, Vec<String>> {
        match value {
            &Value::Table(ref table) => {
                if let Some(&Value::String(ref script)) = table.get("script") {
                    return Ok(PythonRouterConfig {
                        script: script.to_string(),
                    });
                }
            }

            &Value::String(ref script) => {
                return Ok(PythonRouterConfig {
                    script: script.to_string(),
                });
            }

            _ => {}
        }

        Err(vec!["router.python needs to be a string or a table with the key 'script' pointing to the python router script".to_string()])
    }
}
#[derive(Clone)]
pub struct Identity {
    pub key: Bytes,
    pub name: Option<String>,
    pub public_key: Bytes,
}

impl Debug for Identity {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Identity {{ public_key: {:?}, name: {:?} }}", self.public_key, self.name)
    }
}

impl Identity {
    pub fn get_key_pair(&self) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(Input::from(&self.key.clone())).unwrap()
    }

    pub fn sign(&self, msg: &[u8]) -> Bytes {
        return Bytes::from(self.get_key_pair().sign(msg).as_ref());
    }

    pub fn from_value(value: &Value) -> Result<Identity, Vec<String>> {
        let mut error_vec = vec![];

        match value {
            &Value::Table(ref table) => {
                let mut has_errors = false;
                let mut key: Bytes = Bytes::new();
                let mut name: Option<String> = None;

                if table.contains_key("key") {
                    let n = &table["key"];

                    match parse_file_or_value(n, "identity.key", true) {
                        Ok(key_b) => {
                            key = key_b
                        }

                        Err(err) => {
                            error_vec.extend(err);
                            has_errors = true;
                        }
                    }
                } else {
                    error_vec.push(String::from("'identity' is missing value 'key'"));
                    has_errors = true;
                }

                if table.contains_key("name") {
                    let n = &table["name"];

                    if let &Value::String(ref string) = n {
                        name = Some(string.clone());
                    } else {
                        error_vec.push(String::from("'identity.name' should be a string, ignoring value"));
                    }
                }

                if !has_errors {
                    let key_pair = Ed25519KeyPair::from_seed_unchecked(Input::from(&key.clone())).unwrap();

                    return Ok(Identity {
                        name,
                        key,
                        public_key: Bytes::from(key_pair.public_key_bytes()),
                    });
                }
            }

            _ => {
                error_vec.push(String::from("'identity' key expects a table with at least the key 'key' and optionally 'name'"));
            }
        }

        Err(error_vec)
    }
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub threads: u16
}

impl ServerConfig {
    pub fn from_value(value: &Value) -> Result<ServerConfig, Vec<String>> {
        match value {
            &Value::Table(ref table) => {
                let mut threads = 2;

                if let Some(&Value::Integer(ref num)) = table.get("name") {
                    let num = *num;

                    if num < 1 || num > 65535 {
                        return Err(vec!["server.threads needs to be between 1 and 65535".to_string()])
                    }

                    threads = num as u16;
                }

                Ok(ServerConfig {
                    threads
                })
            }

            _ => {
                Err(vec!["server needs to be a table with the key threads".to_string()])
            }
        }
    }
}

#[derive(Clone)]
pub struct Network {
    pub id: [u8; 20],
    pub code: Option<String>,
}

impl Network {
    pub fn from_value(value: &Value) -> Result<Network, Vec<String>> {
        let mut error_vec = vec![];

        match value {
            &Value::Table(ref table) => {
                if table.contains_key("id") {
                    if let &Value::String(ref id_str) = &table["id"] {
                        let id_str = id_str.as_str();

                        if id_str.len() == 40 && id_str.chars().all(|char| char.is_ascii_hexdigit()) {
                            let mut network_id: [u8; 20] = [0; 20];

                            for i in 0..20 {
                                let offset = i * 2;
                                network_id[i] = u8::from_str_radix(&id_str[offset..offset + 2], 16).unwrap();
                            }

                            return Ok(Network {
                                id: network_id,
                                code: None,
                            });
                        }
                    }

                    error_vec.push(String::from("'network.id' key needs to be a 40 letter long hexadecimal string"));
                    return Err(error_vec);
                }

                if table.contains_key("code") {
                    if let &Value::String(ref code_str) = &table["code"] {
                        let digestion = digest::digest(&digest::SHA1, &code_str.clone().into_bytes());
                        let mut network_id: [u8; 20] = [0; 20];
                        network_id.copy_from_slice(&digestion.as_ref()[..20]);

                        return Ok(Network {
                            id: network_id,
                            code: Some(code_str.clone()),
                        });
                    }

                    error_vec.push(String::from("'network.code' key needs to be a string"));
                    return Err(error_vec);
                }
            }

            _ => {
                error_vec.push(String::from("'network' key expects a table with the key 'code' or 'id'"));
            }
        }

        Err(error_vec)
    }
}

impl Debug for Network {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let id = &self.id[..];
        let mut hex_string = String::with_capacity(40);
        let hex = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"];

        for byte in id {
            hex_string.push_str(hex[((byte >> 4) & 15 as u8) as usize]);
            hex_string.push_str(hex[(byte & 15) as usize]);
        }

        write!(f, "Network {{ id: {}, code: {:?} }}", hex_string, self.code)
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub identity: Identity,
    pub interface: Interface,
    pub server: ServerConfig,
    pub auth: Auth,
    pub network: Network,
    pub router: RouterConfig,
}

impl Config {
    pub fn from_value(value: &Value) -> Result<Config, Vec<String>> {
        let mut error_vec = vec![];

        match value {
            &Value::Table(ref table) => {
                let mut auth: Option<Auth> = None;
                let mut identity: Option<Identity> = None;
                let mut network: Option<Network> = None;
                let mut router: Option<RouterConfig> = None;
                let mut interface = Interface {
                    mtu: 1400,
                    mode: Mode::Tun,
                    name: "bw%d".to_string()
                };

                let mut server = ServerConfig {
                    threads: 4,
                };

                let mut has_errors: bool = false;
                if table.contains_key("auth") {
                    match Auth::from_value(&table["auth"]) {
                        Ok(auth_) => {
                            auth = Some(auth_);
                        }

                        Err(err) => {
                            error_vec.extend(err);
                            has_errors = true;
                        }
                    }
                } else {
                    has_errors = true;
                    error_vec.push(String::from("Config is missing 'auth' key"));
                }

                if table.contains_key("interface") {
                    match Interface::from_value(&table["interface"]) {
                        Ok(interf) => {
                            interface = interf;
                        }

                        Err(err) => {
                            error_vec.extend(err);
                            has_errors = true;
                        }
                    }
                }

                if table.contains_key("interface") {
                    match ServerConfig::from_value(&table["server"]) {
                        Ok(serv) => {
                            server = serv;
                        }

                        Err(err) => {
                            error_vec.extend(err);
                            has_errors = true;
                        }
                    }
                }

                if table.contains_key("identity") {
                    match Identity::from_value(&table["identity"]) {
                        Ok(ident) => {
                            identity = Some(ident);
                        }

                        Err(err) => {
                            error_vec.extend(err);
                            has_errors = true;
                        }
                    }
                } else {
                    has_errors = true;
                    error_vec.push(String::from("Config is missing 'identity' key"));
                }

                if table.contains_key("network") {
                    match Network::from_value(&table["network"]) {
                        Ok(net) => {
                            network = Some(net);
                        }

                        Err(err) => {
                            error_vec.extend(err);
                            has_errors = true;
                        }
                    }
                } else {
                    has_errors = true;
                    error_vec.push(String::from("Config is missing 'network' key"));
                }

                if let Some(ref value) = table.get("router") {
                    match RouterConfig::from_value(value) {
                        Ok(rou) => router = Some(rou),
                        Err(err) => {
                            error_vec.extend(err);
                            has_errors = true;
                        }
                    }
                } else {
                    has_errors = true;
                    error_vec.push(String::from("Config is missing 'router' key"));
                }

                if !has_errors {
                    return Ok(Config {
                        router: router.unwrap(),
                        interface,
                        server,
                        auth: auth.unwrap(),
                        identity: identity.unwrap(),
                        network: network.unwrap(),
                    });
                }
            }

            _ => {
                error_vec.push(String::from("Config must be a table."));
            }
        }

        Err(error_vec)
    }
}