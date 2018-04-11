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

fn parse_file_or_value(value: &Value, path: &str) -> Option<Bytes> {
    match value {
        Value::String(string) => {
            return read_file(&string, path);
        }

        Value::Table(table) => {
            if let Some(Value::String(value)) = table.get("value") {
                return Some(Bytes::from(value));
            }

            if let Some(Value::String(file)) = table.get("file") {
                return read_file(&file, path);
            }

            eprintln!("Need a string with the key 'value' or 'file' for {}", path);
        }
    }

    None
}

pub enum Auth {
    Secret(Bytes),
    Authority(Authority),
}

impl Auth {
    pub fn form_value(value: &Value) -> Option<Auth> {
        match value {
            Value::String(string) => {
                return Some(Auth::Secret(Bytes::from(string)));
            }

            Value::Table(table) => {
                if let Some(secret) = table.get("secret") {
                    if Some(bytes) = parse_file_or_value(secret, "auth.secret") {}
                    else {
                        
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

pub struct Authority {
    pub key: Bytes,
    pub authority_key: Bytes,
}

pub struct Config {
    pub auth: Auth
}

impl Config {
    pub fn from_value(value: &Value) -> Option<Config> {
        match value {
            Value::Table(table) => {
                let auth: Auth;
                if table.contains_key("auth") {
                    if let Some(auth) = Auth::from_value(table.get("auth").unwrap()) {}
                } else {
                    eprintln!("Config is missing 'auth' key")
                }
            }

            _ => {
                eprintln!("Config must be a table.")
            }
        }

        None
    }
}