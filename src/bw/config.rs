use std::fs::File;
use std::io::prelude::*;
use std::io;

use bytes::Bytes;
use toml::Value;

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

        _ => {}
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

                if let (Some(own_key_val), Some(authority_key_val)) = (table.get("key"), table.get("authority_key")) {
                    if let (Some(key), Some(authority_key)) = (parse_file_or_value(own_key_val, "auth.key", true), parse_file_or_value(own_key_val, "auth.authority_key", true)) {
                        return Some(Auth::Authority(Authority {
                            key,
                            authority_key,
                        }));
                    }
                }
            }

            _ => {
                eprintln!("'auth' key expects an string, or table with the key 'secret' or keys 'authority_key' and 'key'");
            }
        }

        None
    }
}

#[derive(Debug)]
pub struct Authority {
    pub key: Bytes,
    pub authority_key: Bytes,
}

#[derive(Debug)]
pub struct Config {
    pub auth: Auth
}

impl Config {
    pub fn from_value(value: &Value) -> Option<Config> {
        match value {
            &Value::Table(ref table) => {
                let mut auth: Auth = Auth::Secret(Bytes::from(b"black-widow".to_vec()));
                let mut has_errors: bool = false;
                if table.contains_key("auth") {
                    if let Some(auth_res) = Auth::from_value(table.get("auth").unwrap()) {
                        auth = auth_res;
                    }
                } else {
                    has_errors = true;
                    eprintln!("Config is missing 'auth' key")
                }


                if has_errors {
                    return None;
                }

                return Some(Config {
                    auth,
                });
            }

            _ => {
                eprintln!("Config must be a table.")
            }
        }

        None
    }
}