use std::fs::File;
use std::io::prelude::*;
use std::io;

use bytes::Bytes;
use toml::value::{Value, Table};
use uuid::Uuid;

fn read_file(file_path: &str, path: &str) -> Option<Bytes> {
    let file = File::open(file_path);

    if file.is_err() {
        eprintln!("Couldn't open file '{}' for {}", file_path, path);

        return None;
    }

    let mut file = file.unwrap();

    let mut data: Vec<u8> = vec![0; 1024];
    let size = file.read(&mut data);

    if size.is_err() {
        eprintln!("Couldn't open file '{}' for {}", file_path, path);

        return None;
    }

    let size = size.unwrap();

    Some(Bytes::from(&data[..size]))
}

fn parse_file_or_value(value: &Value, path: &str, default_is_path: bool) -> Option<Bytes> {
    match value {
        &Value::String(ref string) => {
            if default_is_path {
                return read_file(&string, path);
            } else {
                return Some(Bytes::from(string.as_bytes()));
            }
        }

        &Value::Table(ref table) => {
            if let Some(&Value::String(ref value)) = table.get("value") {
                return Some(Bytes::from(value.as_bytes()));
            }

            if let Some(&Value::String(ref file)) = table.get("file") {
                return read_file(&file, path);
            }

            eprintln!("Need a string with the key 'value' or 'file' for {}", path);
        }

        _ => {
            eprintln!("Need a string or table with the key 'value' or 'file' for {}", path);
        }
    }

    None
}

#[derive(Debug)]
pub enum Auth {
    Secret(Bytes),
    Authority(Authority),
}

impl Auth {
    pub fn from_value(value: &Value) -> Option<Auth> {
        match value {
            &Value::String(ref string) => {
                return Some(Auth::Secret(Bytes::from(string.as_bytes())));
            }

            &Value::Table(ref table) => {
                if let Some(secret) = table.get("secret") {
                    if let Some(bytes) = parse_file_or_value(secret, "auth.secret", false) {
                        return Some(Auth::Secret(bytes));
                    }
                }

                if let (Some(own_key_val), Some(authority_key_val)) = (table.get("key"), table.get("signature")) {
                    if let (Some(key), Some(signature)) = (parse_file_or_value(own_key_val, "auth.key", true), parse_file_or_value(own_key_val, "auth.authority_key", true)) {
                        return Some(Auth::Authority(Authority {
                            key,
                            signature,
                        }));
                    }
                }
            }

            _ => {
                eprintln!("'auth' key expects an string, or table with the key 'secret' or keys 'signature' and 'key'");
            }
        }

        None
    }
}

#[derive(Debug)]
pub struct Authority {
    pub key: Bytes,
    pub signature: Bytes,
}

#[derive(Debug)]
pub struct Identity {
    pub key: Bytes,
    pub name: Option<String>,
    pub id: Uuid,
}

impl Identity {
    pub fn from_value(value: &Value) -> Option<Identity> {
        match value {
            &Value::Table(ref table) => {
                let mut has_errors = false;
                let mut key: Bytes = Bytes::new();
                let mut name: Option<String> = None;
                let mut id: Uuid = Uuid::new_v4();

                if table.contains_key("key") {
                    let n = &table["key"];

                    if let Some(b) = parse_file_or_value(n, "identity.key", true) {
                        key = b;
                    } else {
                        has_errors = true;
                    }
                } else {
                    eprintln!("'identity' is missing value 'key'");
                    has_errors = true;
                }

                if table.contains_key("name") {
                    let n = &table["name"];

                    if let &Value::String(ref string) = n {
                        name = Some(string.clone());
                    } else {
                        eprintln!("'identity.name' should be a string, ignoring value");
                    }
                }

                if table.contains_key("id") {
                    let n = &table["id"];

                    if let &Value::String(ref string) = n {
                        let mut uuid_str = string.clone();
                        match Uuid::parse_str(&uuid_str) {
                            Ok(uuid) => {
                                id = uuid;
                            }

                            Err(err) => {
                                eprintln!("'identity.id' failed parsing, invalid uuid");
                                has_errors = true;
                            }
                        }
                    } else {
                        eprintln!("'identity.id' should be a string");
                        has_errors = true;
                    }
                } else {
                    eprintln!("'identity' is missing value 'id'");
                    has_errors = true;
                }

                if !has_errors {
                    return Some(Identity {
                        name,
                        key,
                        id
                    })
                }
            }

            _ => {
                eprintln!("'identity' key expects an table with keys 'key', 'name' and 'id'");
            }
        }

        None
    }
}

#[derive(Debug)]
pub struct Config {
    pub identity: Identity,
    pub auth: Auth,
}

impl Config {
    pub fn from_value(value: &Value) -> Option<Config> {
        match value {
            &Value::Table(ref table) => {
                let mut auth: Option<Auth> = None;
                let mut identity: Option<Identity> = None;
                let mut has_errors: bool = false;
                if table.contains_key("auth") {
                    if let Some(auth_res) = Auth::from_value(&table["auth"]) {
                        auth = Some(auth_res);
                    } else {
                        has_errors = true;
                    }
                } else {
                    has_errors = true;
                    eprintln!("Config is missing 'auth' key");
                }

                if table.contains_key("identity") {
                    if let Some(ident_res) = Identity::from_value(&table["identity"]) {
                        identity = Some(ident_res);
                    } else {
                        has_errors = true;
                    }
                } else {
                    has_errors = true;
                    eprintln!("Config is missing 'identity' key");
                }

                if ! has_errors {
                    return Some(Config {
                        auth: auth.unwrap(),
                        identity: identity.unwrap()
                    });
                }
            }

            _ => {
                eprintln!("Config must be a table.")
            }
        }

        None
    }
}