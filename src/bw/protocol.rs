use byteorder::{BigEndian, ReadBytesExt};
use bytes::{Bytes, ByteOrder};

pub enum FrameType {
    MainlineDHT,
    KeyExchange,
    CipherText,
}

pub fn get_frame_type(data: Bytes) -> FrameType {
    match data[0] {
        100 => FrameType::MainlineDHT,
        101 => FrameType::KeyExchange,
        _ => FrameType::CipherText
    }
}

pub enum Message {
    EthernetFrame(Bytes),
    RPC(RPC),
}


impl Message {
    pub fn from_bytes(data: Bytes) -> Option<Message> {
        None
    }
}

pub enum RPC {}

#[derive(Debug, Clone)]
pub enum KeyExchange {
    Request(Request),
    Answer(Answer),
}

impl KeyExchange {
    pub fn from_bytes(data: Bytes) -> Option<KeyExchange> {
        match data[0] {
            0 => Some(KeyExchange::Request(Request::from_bytes(data.slice_from(1)))),
            1 => Some(KeyExchange::Answer(Answer::from_bytes(data.slice_from(1)))),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Answer {
    pub public_key: Bytes,
    pub secret: Bytes,
    pub proof: Bytes,
    pub version: u8,
    pub features: u64,
}


impl Answer {
    pub fn from_bytes(data: Bytes) -> Answer {
        let pubkey_len = BigEndian::read_u16(&data[0..2]);
        let mut offset: usize = 2;
        let public_key = data.slice(offset, offset + pubkey_len as usize);
        offset += pubkey_len as usize;

        let secret_len = BigEndian::read_u16(&data[offset..offset + 2]);
        offset += 2;
        let secret = data.slice(offset, offset + secret_len as usize);
        offset += secret_len as usize;

        let proof_len = BigEndian::read_u16(&data[offset..offset + 2]);
        offset += 2;
        let proof = data.slice(offset, offset + proof_len as usize);
        offset += proof_len as usize;

        let version = data[offset];
        offset += 1;

        let features = BigEndian::read_u64(&data[offset..offset + 8]);

        Answer {
            public_key,
            secret,
            proof,
            version,
            features,
        }
    }

    pub fn to_bytes(&self, out: &mut [u8]) -> usize {
        let mut offset: usize = 0;

        BigEndian::write_u16(&mut out[0..2], self.public_key.len() as u16);
        offset += 2;

        out[offset..offset+self.public_key.len()].copy_from_slice(&self.public_key);
        offset += self.public_key.len();

        BigEndian::write_u16(&mut out[offset .. offset + 2], 0);
        offset += 2;

        BigEndian::write_u16(&mut out[offset .. offset + 2], 0);
        offset += 2;

        out[offset] = 0;
        offset += 1;

        BigEndian::write_u64(&mut out[offset .. offset + 8], 0);
        offset += 8;

        return offset;
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub public_key: Bytes,
    pub proof: Option<Bytes>,
    pub versions: Vec<u8>,
    pub features: u64,
}

impl Request {
    pub fn from_bytes(data: Bytes) -> Request {
        let pubkey_len = BigEndian::read_u16(&data[0..2]);
        println!("pubkey_len: {:?}", pubkey_len);
        let mut offset: usize = 2;
        let public_key = data.slice(offset, pubkey_len as usize + offset);
        offset += pubkey_len as usize;
        let proof_len = BigEndian::read_u16(&data[offset..offset + 2]);
        offset += 2;

        let proof = match proof_len {
            0 => None,
            _ => Some(data.slice(offset, offset + proof_len as usize)),
        };

        offset += proof_len as usize;

        let versions_len: u8 = data[offset];
        offset += 1;

        let versions = (&data[offset..offset + versions_len as usize]).to_vec();
        offset += versions_len as usize;

        let features = BigEndian::read_u64(&data[offset..offset + 8]);

        Request {
            public_key,
            proof,
            versions,
            features,
        }
    }
}