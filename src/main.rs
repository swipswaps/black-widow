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
extern crate uuid;
extern crate crypto;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate toml;

pub mod bw;

use bw::server::{Server, ServerEvent};
use bw::config::Config;

use tokio_core::reactor::Core;

use tun_tap::{Iface, Mode};
use tun_tap::async::Async as IfaceAsync;
use tokio::net::{UdpSocket, UdpFramed};
use tokio_io::codec::BytesCodec;
use tokio::prelude::*;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::fs::File;
use std::thread::spawn;
use futures::sync::mpsc::{channel, Receiver};
use std::io::prelude::*;
use std::io::{Stdin, Stdout, stdin, stdout};
use std::process::exit;
use std::borrow::Cow;

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

struct Stdio {
    stdout: Stdout,
    stdin_receiver: Receiver<String>,
    stdin_buffer: Vec<u8>,
}

impl Stdio {
    pub fn new() -> Stdio {
        let (sender, receiver) = channel(50);

        spawn(move || {
            let mut sender = sender;
            let stdin = stdin();
            let mut buffer = String::with_capacity(1024);

            while let Ok(read) = stdin.read_line(&mut buffer) {
                sender.try_send(buffer[..read].to_string());
                buffer.truncate(0);
            }
        });

        return Stdio {
            stdin_receiver: receiver,
            stdout: stdout(),
            stdin_buffer: vec![],
        };
    }
}

impl Sink for Stdio {
    type SinkItem = String;
    type SinkError = std::io::Error;

    fn start_send(&mut self, item: <Self as Sink>::SinkItem) -> Result<AsyncSink<<Self as Sink>::SinkItem>, <Self as Sink>::SinkError> {
        print!("{}", item);
        // self.stdout.write(&item.as_ref());

        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Result<Async<()>, <Self as Sink>::SinkError> {
        // self.stdout.flush()?;
        Ok(Async::Ready(()))
    }

    fn close(&mut self) -> Result<Async<()>, <Self as Sink>::SinkError> {
        unimplemented!()
    }
}

fn main() {
    let config = get_config().unwrap();

    println!("Working with config: {:?}", config);

    let core = Core::new().unwrap();
    let iface = Iface::new("bw%d", Mode::Tap).unwrap();
    let tunnel = IfaceAsync::new(iface, &core.handle()).unwrap();
    let socket = UdpSocket::bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)).unwrap();
    println!("Listening on {:?}", socket.local_addr().unwrap());
    let socket_stream = UdpFramed::new(socket, BytesCodec::new());

    let runtime = core.remote();

    let mut server = Server::new(config);

    let mut stdio_thing = Stdio::new();

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

            ServerEvent::Control(data) => {
                print!("{}", data);
            }
        }

        future::ok(())
    });

    let control_pipe_in = stdio_thing.stdin_receiver.map(|data| {
        ServerEvent::Control(data)
    }).map_err(|_| -> std::io::Error {  std::io::Error::last_os_error() });

    let socket_pipe_in = stream_out.map(|(packet, addr)| {
        ServerEvent::Packet(packet.freeze(), addr)
    });

    let tunnel_pipe_in = tunnel_out.map(|data| {
        ServerEvent::Tunnel(Bytes::from(&data[4..]))
    });

    let joined_server_sink = control_pipe_in
        .select(socket_pipe_in)
        .select(tunnel_pipe_in)
        .forward(server_in);

    tokio::run({
        joined_server_sink
            .join(server_out)
            .map(|_| ())
            .map_err(|_| ())
    })
}
