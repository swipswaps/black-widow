extern crate futures;
extern crate tokio;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_udp;
extern crate tun_tap;
extern crate bytes;

pub mod bw;

use bw::server::{Server, ServerEvent};

use tokio_core::reactor::Core;

use tun_tap::{Iface, Mode};
use tun_tap::async::Async;
use tokio::net::{UdpSocket, UdpFramed};
use tokio_io::codec::BytesCodec;
use tokio::prelude::*;
use bytes::Bytes;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn main() {
    let core = Core::new().unwrap();
    let iface = Iface::new("bw%d", Mode::Tap).unwrap();
    let tunnel = Async::new(iface, &core.handle()).unwrap();
    let socket = UdpSocket::bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)).unwrap();
    println!("Listening on {:?}", socket.local_addr().unwrap());
    let socket_stream = UdpFramed::new(socket, BytesCodec::new());

    let runtime = core.remote();

    let server = Server::new();

    let (mut tunnel_in, tunnel_out) = tunnel.split();
    let (mut stream_in, stream_out) = socket_stream.split();
    let (server_in, server_out) = server.split();

    let server_out = server_out.for_each(move |event| {
        match event {
            ServerEvent::Tunnel(data) => {
                tunnel_in.start_send(data);
                tunnel_in.poll_complete();
            }

            ServerEvent::Packet(data, addr) => {
                stream_in.start_send((Bytes::from(data), addr));
                stream_in.poll_complete();
            }
        }

        future::ok(())
    });

    let socket_pipe_in = stream_out.map(|(packet, addr)| {
        ServerEvent::Packet(packet.to_vec(), addr)
    });

    let tunnel_pipe_in = tunnel_out.map(|data| {
        ServerEvent::Tunnel(data)
    });

    let joined_server_sink = socket_pipe_in.select(tunnel_pipe_in).forward(server_in);

    tokio::run({
        server_out.join(joined_server_sink).map(|_| ()).map_err(|_| ())
    })
}

