enum Frame {
    MainlineDHT,
    KeyExchange,
    CipherText,
}

fn get_frame_type(data: Bytes) -> Frame {
    match data[0] {
        'd' => Frame::MainlineDHT,
        'e' => Frame::KeyExchange,
        _ => Frame::CipherText
    }
}

enum Message {
    EthernetFrame(Bytes),
    RPC(RPC),
}


impl Message {
    pub fn from_bytes(data: Bytes) -> Option<Message> {}
}

enum RPC {

}

enum KeyExchange {
    Request(Request),
    Answer(Answer)
}

struct Answer {
    public_key: Bytes,
    secret: Bytes,
    proof: Bytes,
    version: u16
}

struct Request {
    public_key: Bytes,
    proof: Option<Bytes>,
    versions: Bytes
}