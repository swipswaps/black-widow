extern crate tun_tap;

#[macro_use]
extern crate pnet_transport;
extern crate pnet_packet;
extern crate pnet_sys;
extern crate futures;
extern crate futures_mpsc;
extern crate tokio_core;
extern crate tokio;


pub mod bw;

use bw::server::Server;
use bw::tunnel::instance::Tunnel;
use tokio_core::reactor::Core;
use futures::Stream;
use futures::future;
use futures::stream::SplitStream;

use tun_tap::{Iface, Mode};
use tun_tap::async::Async;

fn main() {
    let core = Core::new().unwrap();
    let iface = Iface::new("bw%d", Mode::Tap).unwrap();
    let async = Async::new(iface, &core.handle()).unwrap();
    let tunnel = Tunnel::new(async);
    let mut server = Server::new(tunnel);

    server.listen_all(1500).unwrap();

    tokio::run(future::ok(()));
}

