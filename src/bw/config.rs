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

#[derive(Debug)]
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

#[derive(Debug)]
pub struct Authority {
    pub key: Bytes,
    pub signature: Bytes,
}

pub struct SharedSecret {
    pub secret: Bytes,
    pub signing_key: SigningKey,
}

impl Debug for SharedSecret {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "SharedSecret {{ secret: {:?} }}", self.secret)
    }
}

impl SharedSecret {
    pub fn new(secret: Bytes) -> SharedSecret {
        SharedSecret {
            signing_key: SigningKey::new(&digest::SHA512, &secret),
            secret,
        }
    }
}

pub struct Identity {
    pub key: Bytes,
    pub name: Option<String>,
    pub key_pair: Ed25519KeyPair,
    pub public_key: Bytes,
}

impl Debug for Identity {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Identity {{ public_key: {:?}, name: {:?} }}", self.public_key, self.name)
    }
}

impl Identity {
    pub fn sign(&self, msg: &[u8]) -> Bytes {
        return Bytes::from(self.key_pair.sign(msg).as_ref());
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
                        key_pair,
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

#[derive(Debug)]
pub struct Config {
    pub identity: Identity,
    pub auth: Auth,
    pub network: Network,
}

impl Config {
    pub fn from_value(value: &Value) -> Result<Config, Vec<String>> {
        let mut error_vec = vec![];

        match value {
            &Value::Table(ref table) => {
                let mut auth: Option<Auth> = None;
                let mut identity: Option<Identity> = None;
                let mut network: Option<Network> = None;
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

                if !has_errors {
                    return Ok(Config {
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