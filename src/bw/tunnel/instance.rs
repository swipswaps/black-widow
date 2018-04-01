use tun_tap::async::Async;
use futures::stream::{SplitSink, SplitStream, Stream};

pub struct Tunnel {
    pub sink: SplitSink<Async>,
    pub stream: SplitStream<Async>
}

impl Tunnel {
    pub fn new(async: Async) -> Tunnel {
        let (sink, stream) = async.split();
        Tunnel {
            sink,
            stream
        }
    }
}