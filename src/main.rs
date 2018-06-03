#![feature(proc_macro, specialization, proc_macro_path_invoc, extern_prelude, try_from)]
#![allow(warnings)]
extern crate tun_tap;
extern crate bytes;
extern crate byteorder;
extern crate ring;
extern crate untrusted;
extern crate serde;
extern crate uuid;
extern crate crypto;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate toml;

#[cfg(feature = "python-router")]
extern crate pyo3;

extern crate tokio;
extern crate tokio_core;
extern crate futures;

#[macro_use]
pub mod bw;

use bw::prelude::*;

use tokio_core::reactor::Core;

use tun_tap::{Iface, Mode};

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::fs::File;
use std::time::{Duration, SystemTime, UNIX_EPOCH, Instant};
use std::thread::{Builder, sleep, JoinHandle};
use std::sync::Arc;
use std::sync::mpsc::channel;
use std::io::prelude::*;
use std::io::{Stdin, Stdout, stdin, stdout};
use std::process::exit;
use std::borrow::Cow;
use std::mem;

use bytes::Bytes;

fn get_config() -> Result<Config, Vec<String>> {
    let mut config = File::open("config/example_secret.toml").unwrap();
    let mut contents = String::new();

    config.read_to_string(&mut contents);

    if let Ok(value) = contents.parse::<toml::Value>() {
        return Config::from_value(&value);
    } else {
        return Err(vec![String::from("Failed to load config")]);
    }
}

fn spawn_named<F, T>(name: &str, f: F) -> JoinHandle<T>
    where
        F: FnOnce() -> T,
        F: Send + 'static,
        T: Send + 'static {
    Builder::new()
        .name(name.to_string())
        .spawn(f)
        .unwrap()
}

fn main() {
    let config = get_config().unwrap();

    println!("Working with config: {:#?}", config);

    let core = Core::new().unwrap();
    let iface = Iface::new("bw%d", Mode::Tun).unwrap();
    let name = iface.name().to_string();
    let mut socket = UdpSocket::bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)).unwrap();
    println!("Listening on {:?}", socket.local_addr().unwrap());

    let runtime = core.remote();
    let (all_sender, all_receiver) = channel();

    // let mut server = Server::new(config);
    let mut server = Server::new(config);
    server.set_interface_name(name.to_string());

    let all_writer = all_sender.clone();

    server.set_event_callback(move |event| {
        all_writer.send(event);
    });

    server.ready();

    let (server_sender, server_receiver) = channel();

    let iface = Arc::new(iface);
    let iface_writer = Arc::clone(&iface);
    let iface_reader = Arc::clone(&iface);
    let server_writer = server_sender.clone();

    let iface_reader = spawn_named("interface listener", move || {
        let mut x = vec![0u8; 1700];
        let mut amount = 0;
        let mut amount_now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        loop {
            /* let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

            if now != amount_now {
                println!("read {} packets in 1s", amount);
                amount = 0;
                amount_now = now;
            } */

            if let Ok(size) = iface_reader.recv(&mut x) {
            //    amount += 1;
                server_writer.send(ServerEvent::Tunnel(Bytes::from(&x[..size])));
            }
        }
    });

    let udp = Arc::new(socket);
    let udp_reader = Arc::clone(&udp);
    let udp_writer = Arc::clone(&udp);
    let server_writer = server_sender.clone();

    let udp_reader = spawn_named("udp listener", move || {
        let mut x = vec![0u8; 1500];

        loop {
            if let Ok((size, from)) = udp_reader.recv_from(&mut x) {
                server_writer.send(ServerEvent::Packet(Bytes::from(&x[..size]), from));
            }
        }
    });

    let server_writer = server_sender.clone();
    let stdin_reader = spawn_named("stdin listener", move || {
        let mut input = String::new();
        loop {
            if let Ok(size) = stdin().read_line(&mut input) {
                server_writer.send(ServerEvent::Control(input[..size].to_string()));
                input = String::new();
            }
        }
    });

    let all_reader = spawn_named("server event listener", move || {
        let mut amount = 0;
        let mut amount_now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        loop {
            /*let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

            if now != amount_now {
                println!("Written {} packets in 1s", amount);
                amount = 0;
                amount_now = now;
            }*/

            if let Ok(event) = all_receiver.recv() {
                match event {
                    ServerEvent::Packet(data, addr) => {
                        udp_writer.send_to(data.as_ref(), addr);
                    }

                    ServerEvent::Tunnel(data) => {
                        // amount += 1;
                        iface_writer.send(data.as_ref());
                    }

                    ServerEvent::Control(data) => {
                        println!("{}", data);
                    }
                }
            }
        }
    });

    let mut count: [Vec<u64>; 3] = [vec![], vec![], vec![]];
    let mut last = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    loop {
        /*
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        if now != last {
            let counters = mem::replace(&mut count, [vec![], vec![], vec![]]);

            let mut index = 0;
            for numbers in counters.iter() {
                let mut lowest = std::u64::MAX;
                let mut highest = 0;
                let mut total: f64 = 0f64;

                let len: f64 = numbers.len() as f64;

                for num in numbers {
                    let number = *num;
                    total += number as f64;

                    if lowest > number {
                        lowest = number;
                    }

                    if highest < number {
                        highest = number;
                    }
                }

                println!("{} | l: {} h: {} a: {} c: {}", index, lowest, highest, total / len, len);
                index += 1;
            }

            last = now;
        }*/

        if let Ok(event) = server_receiver.recv() {
            /*
            let index = match event {
                ServerEvent::Control(_) => 2,
                ServerEvent::Packet(_, _) => 1,
                ServerEvent::Tunnel(_) => 0,
            };

            let start = Instant::now();
*/
            server.send_event(event);
  /*          let end = Instant::now();
            let duration = (end - start);


            count[index].push((duration.as_secs() * 1_000_000_000) + duration.subsec_nanos() as u64);*/
        }
    }

    iface_reader.join().unwrap();
    udp_reader.join().unwrap();
    stdin_reader.join().unwrap();
    all_reader.join().unwrap();
}
