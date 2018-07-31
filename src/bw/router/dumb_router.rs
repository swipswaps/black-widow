use super::Router;
use super::super::prelude::*;


use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Mutex, Arc};


#[derive(Clone)]
pub struct DumbRouter {
    remote: Option<ServerRemote>,
    own_id: [u8; 32],
    mac_id_map: Arc<Mutex<HashMap<[u8; 6], [u8; 32]>>>,
}

impl DumbRouter {
    pub fn new() -> DumbRouter {
        DumbRouter {
            remote: None,
            mac_id_map: Arc::new(Mutex::new(HashMap::new())),
            own_id: [0u8; 32],
        }
    }
}

fn slice_to_array_6<T: Copy + Default>(data: &[T]) -> [T; 6] {
    let mut x: [T; 6] = [T::default(); 6];
    &x.copy_from_slice(&data[..6]);
    x
}

fn slice_to_array_32<T: Copy + Default>(data: &[T]) -> [T; 32] {
    let mut x: [T; 32] = [T::default(); 32];
    &x.copy_from_slice(&data[..32]);
    x
}

impl Router<DumbRouter> for DumbRouter {
    fn ready(&mut self, remote: ServerRemote, own_id: Bytes) {
        self.remote = Some(remote);
        &self.own_id.copy_from_slice(&own_id[..32]);
    }

    fn handle_message(&self, message: Message, _addr: SocketAddr, id: Bytes) {
        let cloned_payload = message.payload.clone();
        let dest = &cloned_payload[0..6];
        let source = &cloned_payload[6..12];

        use_item!(self.mac_id_map, mut map => {
            map.insert(slice_to_array_6(source), slice_to_array_32(&id));
        });

        if dest == &[255; 6] {
            if let Some(ref remote) = &self.remote {
                remote.write_packet(message.payload);
            }

            return;
        }

        if use_item!(self.mac_id_map, map => {
            if let Some(ref x) = map.get(dest) {
                x[..] == self.own_id[..]
            } else {
                false
            }
        }) {
            if let Some(ref remote) = &self.remote {
                remote.write_packet(message.payload);
            }
        }
    }

    fn handle_packet(&self, packet: Bytes) {
        let cloned_packet = packet.clone();
        let dest = &packet[0..6];
        let source = &packet[6..12];

        use_item!(self.mac_id_map, mut map => {
            map.insert(slice_to_array_6(source), self.own_id);
        });

        if dest == &[255; 6] {
            if let Some(ref remote) = &self.remote {
                remote.publish_message(Message::new(0, cloned_packet));
            }

            return;
        }

        use_item!(self.mac_id_map, map => {
            if let Some(ref x) = map.get(dest) {
                if let Some(ref remote) = &self.remote {
                    remote.send_message_to_client(
                        Message::new(1, cloned_packet),
                        Bytes::from(&x[..])
                    );
                }
            }
        });
    }
}