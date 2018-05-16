#[macro_use]
pub mod macros {
    #[macro_export]
    macro_rules! use_item {
        ($which:expr, $name:tt => $with:expr) => {
            {
                let __arc = $which.clone();
                let mut $name = __arc.lock().unwrap();

                $with
            }
        };

        ($which:expr, $with:expr) => {
            {
                let __arc = $which.clone();
                let mut $which = __arc.lock().unwrap();

                $with
            }
        };
    }
}

pub mod node;
pub mod server;
pub mod vec_stream;
pub mod packet;
pub mod protocol;
pub mod config;
pub mod router;

pub mod prelude {
    pub use super::protocol::{Message, EncryptedMessage, PacketType, Packet};
    pub use super::server::{ServerEvent, Server, ConnectionState, ConnectionInfo, MutexConnectionInfo};
    pub use super::config::*;
    pub use super::packet;
    #[macro_use]
    pub use super::macros;
}