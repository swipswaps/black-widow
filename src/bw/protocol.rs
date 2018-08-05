use byteorder::{BigEndian, WriteBytesExt};
use bytes::{Bytes, ByteOrder, BytesMut};

use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{VerificationAlgorithm, ED25519};
use ring::agreement::{X25519, agree_ephemeral, EphemeralPrivateKey};
use ring::hkdf::extract_and_expand;
use ring::hmac::{SigningKey, sign, verify_with_own_key};
use ring::digest::{SHA512, SHA1};
use ring::error::Unspecified;
use untrusted::Input;
use super::prelude::*;

use std::io::prelude::*;
use std::io::Cursor;

use crypto::chacha20::ChaCha20;
use crypto::symmetriccipher::SynchronousStreamCipher;

#[derive(Clone, Debug)]
pub struct EncryptionParameters {
    authentication_key: Bytes,
    encryption_key: Bytes,
}

impl EncryptionParameters {
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::new(&SHA1, &self.authentication_key)
    }

    pub fn from_bytes(data: Bytes) -> Option<EncryptionParameters> {
        if data.len() < 64 {
            return None;
        }

        return Some(EncryptionParameters {
            authentication_key: data.slice(0, 32),
            encryption_key: data.slice(32, 64),
        });
    }
}

pub enum Packet {
    MainlineDHT(Bytes),
    KeyExchange(KeyExchange),
    EncryptedMessage(EncryptedMessage),
}

macro_rules! verify_ed25519 {
    ($key:expr, $msg:expr, $signature:expr) => {
        let algo = &ED25519;
        if let Err(_) = algo.verify(Input::from($key), Input::from($msg), Input::from($signature)) {
             return false
        }
    };
}

impl Packet {
    pub fn from_bytes(data: Bytes) -> Option<Packet> {
        if data.len() < 1 {
            return None;
        }

        let payload = data.slice_from(1);

        let res = Packet::get_frame_type(data[0]);

        match res {
            Some(PacketType::EncryptedMessage) => {
                if let Some(message) = EncryptedMessage::from_bytes(payload) {
                    Some(Packet::EncryptedMessage(message))
                } else {
                    None
                }
            }

            Some(PacketType::KeyExchange) => {
                if let Some(key_exchange) = KeyExchange::from_bytes(payload) {
                    Some(Packet::KeyExchange(key_exchange))
                } else {
                    None
                }
            }

            Some(PacketType::MainlineDHT) => {
                Some(Packet::MainlineDHT(data))
            }

            // Is actually only None
            _ => None,
        }
    }

    pub fn size(&self) -> usize {
        match *self {
            Packet::KeyExchange(ref key_exchange) => key_exchange.size() + 1,
            Packet::EncryptedMessage(ref encrypted_message) => encrypted_message.size() + 1,
            Packet::MainlineDHT(ref bytes) => bytes.len()
        }
    }

    pub fn get_bytes(&self) -> Option<Bytes> {
        let mut out = BytesMut::with_capacity(self.size());
        unsafe {
            out.set_len(self.size())
        }

        if let Some(_) = self.to_bytes(&mut out) {
            return Some(out.freeze());
        }

        None
    }

    pub fn to_bytes(&self, out: &mut [u8]) -> Option<usize> {
        if self.size() > out.len() {
            return None;
        }

        match *self {
            Packet::KeyExchange(ref key_exchange) => {
                out[0] = 101;
                if let Some(written) = key_exchange.to_bytes(&mut out[1..]) {
                    return Some(written + 1);
                }
            }

            Packet::EncryptedMessage(ref encrypted_message) => {
                out[0] = 99;
                if let Some(written) = encrypted_message.to_bytes(&mut out[1..]) {
                    return Some(written + 1);
                }
            }

            Packet::MainlineDHT(ref data) => {
                out[..data.len()].copy_from_slice(&data);
            }
        }

        None
    }

    pub fn get_frame_type(identifier: u8) -> Option<PacketType> {
        match identifier {
            99 => Some(PacketType::EncryptedMessage),
            100 => Some(PacketType::MainlineDHT),
            101 => Some(PacketType::KeyExchange),
            _ => None,
        }
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub enum PacketType {
    MainlineDHT,
    KeyExchange,
    EncryptedMessage,
}

#[inline]
fn chacha20(key: &[u8], iv: &[u8], cipher_text: &[u8]) -> Bytes {
    let mut chacha = ChaCha20::new(key, iv);
    let mut output = BytesMut::with_capacity(cipher_text.len());
    unsafe {
        output.set_len(cipher_text.len());
    }

    chacha.process(&cipher_text, &mut output);

    return output.freeze();
}

#[derive(Debug)]
pub struct EncryptedMessage {
    pub packet_id: u64,
    pub iv: Bytes,
    pub cipher_text: Bytes,
}

impl EncryptedMessage {
    pub fn from_bytes(data: Bytes) -> Option<EncryptedMessage> {
        if data.len() < 45 {
            return None;
        }

        Some(EncryptedMessage {
            packet_id: BigEndian::read_u64(&data[0..8]),
            iv: data.slice(8, 20),
            cipher_text: data.slice_from(20),
        })
    }

    pub fn new_from_message(packet_id: u64, message: &Message, parameters: &EncryptionParameters) -> EncryptedMessage {
        let mut iv = [0; 12];
        SystemRandom::new().fill(&mut iv).unwrap();

        let mut message_clone = message.clone();
        message_clone.sign(parameters);

        let mut plain_text = BytesMut::with_capacity(message_clone.size());
        unsafe { plain_text.set_len(message_clone.size()); }

        message_clone.to_bytes(&mut plain_text);
        let cipher_text = chacha20(&parameters.encryption_key, &iv, &plain_text);

        EncryptedMessage {
            iv: Bytes::from(&iv[..]),
            cipher_text,
            packet_id,
        }
    }

    pub fn decrypt(&self, parameters: &EncryptionParameters) -> Option<Message> {
        Message::from_bytes(
            chacha20(
                &parameters.encryption_key,
                &self.iv,
                &self.cipher_text,
            )
        )
    }

    pub fn size(&self) -> usize { 20 + self.cipher_text.len() }

    pub fn to_bytes(&self, out: &mut [u8]) -> Option<usize> {
        if out.len() < self.size() {
            return None;
        }

        let mut cursor = Cursor::new(out);
        cursor.write_u64::<BigEndian>(self.packet_id).unwrap();
        cursor.write(&self.iv).unwrap();
        cursor.write(&self.cipher_text).unwrap();

        Some(cursor.position() as usize)
    }
}


#[derive(Clone, Debug)]
pub struct Message {
    pub compressed: bool,
    pub message_type: u8,
    pub payload: Bytes,
    pub hmac: Bytes,
}

impl Message {
    pub fn new(message_type: u8, payload: Bytes) -> Message {
        Message {
            compressed: false,
            message_type,
            payload,
            hmac: Bytes::new(),
        }
    }

    pub fn from_bytes(data: Bytes) -> Option<Message> {
        let hmac_start = data.len() - 20;
        let hmac = data.slice_from(hmac_start);
        let payload = data.slice(1, hmac_start);

        Some(Message {
            compressed: (data[0] & 128) == 128,
            message_type: data[0] & 127,
            payload,
            hmac,
        })
    }

    pub fn verify(&self, parameters: &EncryptionParameters) -> bool {
        if let Err(_) = verify_with_own_key(&parameters.signing_key(), &self.payload, &self.hmac) {
            return false;
        }

        true
    }

    pub fn size(&self) -> usize {
        return 21 + self.payload.len();
    }

    pub fn sign(&mut self, parameters: &EncryptionParameters) {
        self.hmac = Bytes::from(sign(&parameters.signing_key(), &self.payload).as_ref());
    }

    pub fn to_bytes(&self, out: &mut [u8]) -> Option<usize> {
        if out.len() < self.size() {
            return None;
        }

        let mut cursor = Cursor::new(out);
        cursor.write_u8({ if self.compressed { 128 } else { 0 } } + (self.message_type as u8 & 127)).unwrap();
        cursor.write(&self.payload).unwrap();
        cursor.write(&self.hmac).unwrap();

        Some(cursor.position() as usize)
    }
}

#[derive(Debug, Clone, PartialOrd, PartialEq)]
pub enum KeyExchangeAuthType {
    SharedSecret,
    Authority,
}

#[derive(Debug, Clone)]
pub struct KeyExchange {
    pub version: u8,
    pub public_key: Bytes,
    pub ephemeral_key: Bytes,
    pub ephemeral_signature: Bytes,
    pub auth_type: KeyExchangeAuthType,
    pub proof: Bytes,
}

impl KeyExchange {
    pub fn size(&self) -> usize {
        194
    }

    pub fn from_bytes(data: Bytes) -> Option<KeyExchange> {
        if data.len() < 194 || data[0] != 1 || data[129] > 1 {
            return None;
        }

        Some(KeyExchange {
            version: data[0],
            public_key: data.slice(1, 33),
            ephemeral_key: data.slice(33, 65),
            ephemeral_signature: data.slice(65, 129),
            auth_type: {
                if data[129] == 1 {
                    KeyExchangeAuthType::SharedSecret
                } else {
                    KeyExchangeAuthType::Authority
                }
            },
            proof: data.slice(130, 194),
        })
    }

    pub fn verify_lengths(&self) -> bool {
        if self.public_key.len() != 32 {
            return false;
        }

        if self.ephemeral_key.len() != 32 {
            return false;
        }

        if self.ephemeral_signature.len() != 64 {
            return false;
        }

        if self.proof.len() != 64 {
            return false;
        }

        true
    }

    pub fn to_bytes(&self, out: &mut [u8]) -> Option<usize> {
        if out.len() < 194 || !self.verify_lengths() {
            return None;
        }

        let mut cursor = Cursor::new(out);

        cursor.write_u8(self.version).unwrap();
        cursor.write(&self.public_key).unwrap();
        cursor.write(&self.ephemeral_key).unwrap();
        cursor.write(&self.ephemeral_signature).unwrap();
        cursor.write_u8({
            if self.auth_type == KeyExchangeAuthType::SharedSecret {
                1
            } else {
                0
            }
        }).unwrap();
        cursor.write(&self.proof).unwrap();

        Some(194)
    }

    pub fn verify(&self, config: &Config) -> bool {
        if self.version != 1 {
            return false;
        }

        verify_ed25519!(&self.public_key, &self.ephemeral_key, &self.ephemeral_signature);

        match &config.auth {
            &AuthConfig::CertificateAuthorityConfig(ref authority) => {
                if self.auth_type != KeyExchangeAuthType::Authority {
                    return false;
                }

                verify_ed25519!(&authority.ca.get_value().unwrap(), &self.public_key, &self.proof);
            }

            &AuthConfig::SharedSecretConfig(ref secret) => {
                if self.auth_type != KeyExchangeAuthType::SharedSecret {
                    return false;
                }

                if let Err(_) = verify_with_own_key(&SigningKey::new(&SHA512, &secret.get_secret()), &self.ephemeral_key, &self.proof) {
                    return false;
                }
            }
        }

        true
    }

    pub fn derive_encryption_parameters(&self, ephemeral_key: EphemeralPrivateKey, config: &Config) -> Option<EncryptionParameters> {
        let mut out: Vec<u8> = vec![0; 64];

        if let Err(_) = agree_ephemeral(
            ephemeral_key,
            &X25519,
            Input::from(&self.ephemeral_key),
            Unspecified,
            |key_material| {
                extract_and_expand(&SigningKey::new(&SHA512, &[0; 64]), key_material, &config.get_network_id(), &mut out);

                Ok(())
            },
        ) {
            return None;
        }

        return Some(EncryptionParameters {
            authentication_key: Bytes::from(&out[..32]),
            encryption_key: Bytes::from(&out[32..64]),
        });
    }

    pub fn new_key_exchange(config: &Config) -> Result<(KeyExchange, EphemeralPrivateKey), Unspecified> {
        let ephemeral_key = EphemeralPrivateKey::generate(&X25519, &SystemRandom::new())?;
        let mut ephemeral_public_key = vec![0; 32];
        ephemeral_key.compute_public_key(&mut ephemeral_public_key)?;
        let ephemeral_public_key = Bytes::from(ephemeral_public_key);

        Ok((
            KeyExchange {
                version: 1,
                public_key: config.get_public_key(),
                ephemeral_key: ephemeral_public_key.clone(),
                ephemeral_signature: Bytes::from(config.get_key_pair().sign(&ephemeral_public_key).as_ref()),
                auth_type: {
                    if let AuthConfig::SharedSecretConfig(_) = config.auth {
                        KeyExchangeAuthType::SharedSecret
                    } else {
                        KeyExchangeAuthType::Authority
                    }
                },
                proof: {
                    match &config.auth {
                        &AuthConfig::SharedSecretConfig(ref secret) => {
                            Bytes::from(sign(&SigningKey::new(&SHA512, &secret.get_secret()), &ephemeral_public_key).as_ref())
                        }

                        &AuthConfig::CertificateAuthorityConfig(ref auth) => {
                            auth.signature.get_value().unwrap()
                        }
                    }
                },
            },
            ephemeral_key,
        ))
    }
}

#[cfg(test)]
mod test {
    use ring::signature::Ed25519KeyPair;

    use super::*;

    #[test]
    fn test_shared_secret_key_exchange() {
        let config = Config::from_value(&toml!(
        [network]
        code = "secret society"

        [auth]
        secret = { value = "YiiBoi2018" }

        [identity]
        key = { value = "12345678901234567890123456789012" }
        name = "Starving Califlower"
    )).unwrap();

        let message = KeyExchange::new_key_exchange(&config);
        assert!(message.is_ok());
        let (message, _) = message.unwrap();


        assert!(message.verify(&config));
        let mut compiled_message: Vec<u8> = vec![0; 194];
        assert_eq!(message.to_bytes(&mut compiled_message), Some(194));
        let parsed_message = KeyExchange::from_bytes(Bytes::from(compiled_message));
        assert!(parsed_message.is_some());
        let parsed_message = parsed_message.unwrap();
        assert!(parsed_message.verify(&config));
    }

    #[test]
    fn test_authority_key_exchange() {
        let config = Config::from_value(&toml!(
        [network]
        code = "secret society"

        [auth]
        key = { value = "generated by code" }
        signature = { value = "generated by code" }

        [identity]
        key = { value = "12345678901234567890123456789012" }
        name = "Starving Califlower"
    ));

        if let Err(errs) = config {
            println!("Failed: {:?}", errs);
            assert!(false);
            return;
        }

        let mut config = config.unwrap();

        if let Auth::Authority(ref mut auth) = config.auth {
            let mut authority = vec![0; 32];
            SystemRandom::new().fill(&mut authority).unwrap();
            let authority = Bytes::from(authority);

            let key_pair = Ed25519KeyPair::from_seed_unchecked(Input::from(&authority));
            assert!(key_pair.is_ok());
            let key_pair = key_pair.unwrap();

            auth.signature = Bytes::from(key_pair.sign(&config.identity.public_key).as_ref());
            auth.key = Bytes::from(key_pair.public_key_bytes());
        } else {
            assert!(false);
        }

        let config = config;

        let message = KeyExchange::new_key_exchange(&config);
        assert!(message.is_ok());
        let (message, _) = message.unwrap();

        assert_eq!(&message.public_key, &config.identity.public_key);

        assert!(message.verify(&config));
        let mut compiled_message: Vec<u8> = vec![0; 194];
        assert_eq!(message.to_bytes(&mut compiled_message), Some(194));
        let parsed_message = KeyExchange::from_bytes(Bytes::from(compiled_message));
        assert!(parsed_message.is_some());
        let parsed_message = parsed_message.unwrap();
        assert!(parsed_message.verify(&config));
    }

    #[test]
    fn test_message() {
        let mut all = vec![0; 64];
        SystemRandom::new().fill(&mut all).unwrap();

        let parameters = EncryptionParameters::from_bytes(Bytes::from(all));

        assert!(parameters.is_some());
        let parameters = parameters.unwrap();

        let message = Message {
            compressed: false,
            message_type: 0,
            payload: Bytes::from(b"Hello world!".to_vec()),
            hmac: Bytes::new(),
        };

        let encrypted = EncryptedMessage::new_from_message(1, &message, &parameters);

        let new_message = encrypted.decrypt(&parameters);
        assert!(new_message.is_some());
        let new_message = new_message.unwrap();

        assert_eq!(&new_message.payload, &message.payload);
        assert!(new_message.verify(&parameters));
    }
}