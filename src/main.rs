#![cfg_attr(feature = "python-router", feature(use_extern_macros))]

extern crate tun_tap;
extern crate bytes;
extern crate byteorder;
extern crate ring;
extern crate untrusted;
extern crate uuid;
extern crate crypto;
extern crate futures;

extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate docopt;
extern crate crossbeam_channel;
extern crate toml;

#[cfg(feature = "python-router")]
extern crate pyo3;

#[cfg(feature = "python-router")]
extern crate nix;

#[cfg(feature = "python-router")]
use nix::sys::signal;

#[macro_use]
pub mod bw;

use docopt::Docopt;

use bw::prelude::*;
#[cfg(feature = "python-router")]
use bw::router::use_python;

use tun_tap::{Iface, Mode};

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket, Shutdown};
use std::os::unix::net::{UnixStream, UnixListener};
use std::path::Path;
use std::fs::{File, remove_file};
use std::thread::{Builder, JoinHandle, spawn};
use std::sync::Arc;
use std::sync::mpsc;
use std::io::prelude::*;
use std::io::{stdin, BufReader};
#[cfg(feature = "python-router")]
use std::process::exit;
use std::process::Command;

use bytes::Bytes;

use crossbeam_channel as channel;

const USAGE: &'static str = "
bw - Black Widow

Usage:
    bw daemon [--config <config>]
    bw display-config [--config <config>]
    bw [options]

Options:
    -h, --help  Display this help
";

const DEFAULT_CONFIG: &'static str = "/etc/bw/config.toml";

#[derive(Deserialize)]
struct Args {
    arg_config: Option<String>,
    cmd_daemon: bool,
    cmd_display_config: bool,
}

fn main() {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.argv(std::env::args().into_iter()).deserialize())
        .unwrap_or_else(|e| e.exit());


    #[cfg(feature = "python-router")] unsafe {
        let sig_action = signal::SigAction::new(signal::SigHandler::Handler(handle_sigint),
                                                signal::SaFlags::empty(),
                                                signal::SigSet::empty());
        signal::sigaction(signal::SIGINT, &sig_action).unwrap();
    }

    if args.cmd_daemon {
        let config = get_config(&args.arg_config.clone().unwrap_or(DEFAULT_CONFIG.to_string())).unwrap();
        run_daemon(config);

        return;
    }

    if args.cmd_display_config {
        let config = get_config(&args.arg_config.clone().unwrap_or(DEFAULT_CONFIG.to_string())).unwrap();
        println!("{}", toml::to_string(&toml::Value::try_from(&config).unwrap()).unwrap());

        return;
    }

    println!("No command given. see --help for more info");
}


fn run_daemon(config: Config) {
    let iface = {
        if config.interface.mode == InterfaceConfigMode::Tun {
            Iface::new(config.interface.name.as_str(), Mode::from(config.interface.mode.clone())).unwrap()
        } else {
            Iface::without_packet_info(config.interface.name.as_str(), Mode::from(config.interface.mode.clone())).unwrap()
        }
    };

    let name = iface.name().to_string();

    cmd("ip", &["link", "set", iface.name(), "mtu", format!("{}", config.interface.mtu).as_str()]);

    let socket = UdpSocket::bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)).unwrap();
    println!("Listening on {:?}", socket.local_addr().unwrap());


    let (all_sender, all_receiver) = mpsc::channel();
    let (server_sender, server_receiver) = channel::bounded::<ServerEvent>(1000);

    let thread_cnt = config.server.threads;

    let mut server = RouterUnawareServer::new(config.clone());
    server.set_interface_name(name.to_string());

    let all_writer = all_sender.clone();

    server.set_sender(all_writer);

    server.ready();

    let iface = Arc::new(iface);
    let iface_writer = Arc::clone(&iface);
    let iface_reader = Arc::clone(&iface);
    let server_writer = server_sender.clone();

    let iface_reader = spawn_named("interface listener", move || {
        let mut x = vec![0u8; 1700];

        loop {
            if let Ok(size) = iface_reader.recv(&mut x) {
                server_writer.send(ServerEvent::Tunnel(Bytes::from(&x[..size])));
            }
        }
    });

    let udp = Arc::new(socket);
    let udp_reader = Arc::clone(&udp);
    let udp_writer = Arc::clone(&udp);
    let server_writer = server_sender.clone();

    unix_listener(&config, server.clone());

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
        while let Ok(event) = all_receiver.recv() {
            match event {
                ServerEvent::Packet(data, addr) => {
                    udp_writer.send_to(data.as_ref(), addr).unwrap();
                }

                ServerEvent::Tunnel(data) => {
                    iface_writer.send(data.as_ref()).unwrap();
                }

                ServerEvent::Control(data) => {
                    println!("{}", data);
                }
            }
        }
    });

    let mut threads = vec![];


    println!("Starting {} digestion threads", thread_cnt);

    for i in 0..thread_cnt {
        let serv_recv = server_receiver.clone();
        let server_clone = server.clone();
        threads.push(spawn_named(&format!("server digestion {}", i), move || {
            while let Some(event) = serv_recv.recv() {
                server_clone.send_event(event);
            }
        }));
    }

    for thread in threads {
        thread.join().unwrap();
    }

    iface_reader.join().unwrap();
    udp_reader.join().unwrap();
    stdin_reader.join().unwrap();
    all_reader.join().unwrap();
}

#[cfg(feature = "python-router")]
extern fn handle_sigint(_: i32) {
    // Acquire python lock and die, otherwise python will keep black-widow alive
    use_python(|| {
        exit(0)
    })
}

fn unix_listener(config: &Config, server: RouterUnawareServer) {
    if None == config.server.unix_socket {
        return;
    }

    let config = config.clone();
    let path = config.server.unix_socket.unwrap();

    if Path::new(&path).exists() {
        remove_file(&path).unwrap();
    }

    let socket = UnixListener::bind(&path).unwrap();

    spawn_named("unix listener", move || {
        for stream in socket.incoming() {
            match stream {
                Ok(stream) => {
                    let server_clone = server.clone();
                    spawn(|| handle_client(stream, server_clone));
                }
                Err(_) => {
                    break;
                }
            }
        }
    });

    fn handle_client(mut stream: UnixStream, server: RouterUnawareServer) {
        loop {
            let input = {
                let mut input = String::new();
                let mut reader = BufReader::new(&stream);
                if let Ok(size) = reader.read_line(&mut input) {
                    input[..size].to_string()
                } else {
                    break;
                }
            };

            let output = format!("{}\n", server.handle_control(input));
            &stream.write(&output.into_bytes());
        }

        stream.shutdown(Shutdown::Both).unwrap();
    }
}

fn cmd(cmd: &str, args: &[&str]) {
    let ecode = Command::new(cmd)
        .args(args)
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    assert!(ecode.success(), "Failed to execte {}", cmd);
}

fn get_config(path: &str) -> Result<Config, Vec<String>> {
    let mut config = File::open(path).unwrap();
    let mut contents = String::new();

    config.read_to_string(&mut contents).unwrap();

    let mut config: Config = toml::from_str(&contents).unwrap();

    config.load().unwrap();

    Ok(config)
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