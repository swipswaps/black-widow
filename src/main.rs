extern crate futures;
extern crate tokio;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_udp;
extern crate tun_tap;
extern crate bytes;
extern crate byteorder;
extern crate ring;
extern crate untrusted;
extern crate serde;

#[macro_use]
extern crate serde_derive;
extern crate toml;

pub mod bw;

use bw::server::{Server, ServerEvent};
use bw::config::Config;

use tokio_core::reactor::Core;

use tun_tap::{Iface, Mode};
use tun_tap::async::Async;
use tokio::net::{UdpSocket, UdpFramed};
use tokio_io::codec::BytesCodec;
use tokio::prelude::*;
use bytes::Bytes;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::fs::File;
use std::io::prelude::*;
use std::process::exit;

fn get_config() -> Option<Config> {
    let mut config = File::open("config/example_secret.toml").unwrap();
    let mut contents = String::new();

    config.read_to_string(&mut contents);

    if let Ok(value) = contents.parse::<toml::Value>() {
        if let Some(config) = Config::from_value(&value) {
            return Some(config);
        } else {
            eprintln!("Failed to load config");
            exit(1);
            return None;
        }
    } else {
        eprintln!("Failed to load config");
        exit(1);
        return None;
    }
}

fn main() {

    let config = get_config().unwrap();

    println!("Working with config: {:?}", config);

    let core = Core::new().unwrap();
    let iface = Iface::new("bw%d", Mode::Tap).unwrap();
    let tunnel = Async::new(iface, &core.handle()).unwrap();
    let socket = UdpSocket::bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 55555)).unwrap();
    println!("Listening on {:?}", socket.local_addr().unwrap());
    let socket_stream = UdpFramed::new(socket, BytesCodec::new());

    let runtime = core.remote();

    let server = Server::new(config);

    let (mut tunnel_in, tunnel_out) = tunnel.split();
    let (mut stream_in, stream_out) = socket_stream.split();
    let (server_in, server_out) = server.split();

    let server_out = server_out.for_each(move |event| {
        println!("Event out: {:?}", event);

        match event {
            ServerEvent::Tunnel(data) => {
                tunnel_in.start_send(data.to_vec());
                tunnel_in.poll_complete();
            }

            ServerEvent::Packet(data, addr) => {
                stream_in.start_send((data, addr));
                stream_in.poll_complete();
            }
        }

        future::ok(())
    });

    let socket_pipe_in = stream_out.map(|(packet, addr)| {
        ServerEvent::Packet(packet.freeze(), addr)
    });

    let tunnel_pipe_in = tunnel_out.map(|data| {
        ServerEvent::Tunnel(Bytes::from(data))
    });

    let joined_server_sink = socket_pipe_in.select(tunnel_pipe_in).forward(server_in);

    tokio::run({
        server_out.join(joined_server_sink).map(|_| ()).map_err(|_| ())
    })
}

