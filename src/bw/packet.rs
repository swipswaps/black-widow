use std::net::{Ipv4Addr, Ipv6Addr};
use std::fmt::{Debug, Formatter};
use std::fmt;
use bytes::Bytes;

#[derive(Debug)]
pub struct MacAddress(u8, u8, u8, u8, u8, u8);

impl MacAddress {
    pub fn from_slice(address: &[u8]) -> MacAddress {
        assert_eq!(address.len(), 6);

        MacAddress(address[0], address[1], address[2], address[3], address[4], address[5])
    }
}

pub struct EtherType(u16);

impl EtherType {
    pub fn is_size(&self) -> bool { self.0 <= 1500 }
    pub fn is_tag(&self) -> bool { self.0 == 0x8100 }
    pub fn is_ipv4_frame(&self) -> bool { self.0 == 0x0800 }
    pub fn is_ipv6_frame(&self) -> bool { self.0 == 0x86DD }
    pub fn is_arp_frame(&self) -> bool { self.0 == 0x0806 }
}

impl Debug for EtherType {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "EtherType(0x{:04x})", self.0)
    }
}

#[derive(Debug)]
pub enum PCP {
    BestEffort = 0,
    Background = 1,
    ExcellentEffort = 2,
    CriticalApplication = 3,
    Video = 4,
    Voice = 5,
    InternetworkControl = 6,
    NetworkControl = 7,
}

#[derive(Debug)]
pub struct QTag {
    inner: Bytes,
}

impl QTag {
    pub fn pcp(&self) -> PCP {
        match self.inner[0] & 7 {
            0 => PCP::BestEffort,
            1 => PCP::Background,
            2 => PCP::ExcellentEffort,
            3 => PCP::CriticalApplication,
            4 => PCP::Video,
            5 => PCP::Voice,
            6 => PCP::InternetworkControl,
            7 => PCP::NetworkControl,
            _ => PCP::BestEffort,
        }
    }

    pub fn dei(&self) -> bool {
        (self.inner[2] & 8) == 8
    }

    pub fn vlan_id(&self) -> u16 {
        (u16::from(self.inner[2] & 240) >> 4) + (u16::from(self.inner[3]) << 4)
    }

    pub fn from_bytes(data: Bytes) -> Option<QTag> {
        assert_eq!(data.len(), 4);

        if u16::from(data[0]) + (u16::from(data[1]) << 8) == 0x8100 {
            return Some(QTag { inner: data });
        }

        return None;
    }

    pub fn from_slice(data: &[u8]) -> Option<QTag> {
        QTag::from_bytes(Bytes::from(data))
    }
}

#[derive(Debug)]
pub enum EthernetPayload {
    Ipv4Frame(Ipv4Frame),
    Ipv6Frame(Ipv6Frame),
    ARP(ARPFrame),
    Data(Bytes),
}

pub struct EthernetPacket {
    inner: Bytes,
}

impl EthernetPacket {
    pub fn from_bytes(data: Bytes) -> EthernetPacket {
        EthernetPacket {
            inner: data,
        }
    }

    pub fn destination_address(&self) -> MacAddress {
        return MacAddress::from_slice(&self.inner[..6]);
    }

    pub fn source_address(&self) -> MacAddress {
        return MacAddress::from_slice(&self.inner[6..12]);
    }

    fn read_ether_type_at(&self, index: usize) -> EtherType {
        return EtherType((u16::from(self.inner[index]) << 8) + u16::from(self.inner[index + 1]));
    }

    fn first_ether_type(&self) -> EtherType {
        return self.read_ether_type_at(12);
    }

    pub fn ether_type(&self) -> EtherType {
        let first_ether_type = self.first_ether_type();
        if first_ether_type.is_tag() {
            return self.read_ether_type_at(16);
        }

        return first_ether_type;
    }

    pub fn tag(&self) -> Option<QTag> {
        return QTag::from_bytes(self.inner.slice(12, 16));
    }

    pub fn header_size(&self) -> usize {
        if let Some(_) = self.tag() {
            return 18;
        }

        return 14;
    }

    pub fn size(&self) -> usize {
        0
    }

    pub fn crc(&self) -> Bytes {
        self.inner.slice_from(self.inner.len() - 4)
    }

    pub fn payload(&self) -> EthernetPayload {
        let data = self.inner.slice(self.header_size(), self.inner.len() - 4);

        let ether_type = &self.ether_type();

        match ether_type {
            // ether_type if ether_type.is_arp_frame() => {}

            // ether_type if ether_type.is_ipv4_frame() => {}

            ether_type if ether_type.is_ipv6_frame() => {
                return EthernetPayload::Ipv6Frame(Ipv6Frame::from_bytes(data));
            }

            _ => {
                return EthernetPayload::Data(data);
            }
        }
    }
}

impl Debug for EthernetPacket {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "EthernetPacket {{ source_address: {:?}, destination_address: {:?}, ether_type: {:?}, payload: {:?} }}", self.source_address(), self.destination_address(), self.ether_type(), self.payload())
    }
}

#[derive(Debug)]
pub struct ARPFrame {
    hardware_type: u16,
    protocol_type: u16,
    hardware_address_length: u8,
    protocol_address_length: u8,
    operation: u16,
    sender_hardware_address: Bytes,
    sender_protocol_address: Bytes,
    target_hardware_address: Bytes,
    target_protocol_address: Bytes,
}

#[derive(Debug)]
pub struct Ipv4Frame {
    version: u8,
    ihl: u8,
    dscp: u8,
    ecn: u8,
    total_length: u16,
    id: u16,
    flags: u8,
    fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    header_checksum: u16,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    options: Vec<u8>,
    payload: Vec<u8>,
}

#[derive(Debug)]
pub struct Ipv6Frame {
    inner: Bytes,
}

impl Ipv6Frame {
    pub fn version(&self) -> u8 {
        self.inner[0] & 15
    }

    pub fn traffic_class(&self) -> u8 {
        ((self.inner[0] & 240) >> 4) + ((self.inner[1] & 15) << 4)
    }

    pub fn flow_label(&self) -> u32 {
        ((u32::from(self.inner[1]) & 240) >> 4) + (u32::from(self.inner[2]) << 4) + (u32::from(self.inner[3]) << 12)
    }

    pub fn payload_length(&self) -> u16 {
        u16::from(self.inner[4]) + (u16::from(self.inner[5]) << 8)
    }

    pub fn next_header(&self) -> u8 {
        self.inner[6]
    }

    pub fn hop_limit(&self) -> u8 {
        self.inner[7]
    }

    fn read_ipv6_at(&self, index: usize) -> Ipv6Addr {
        let mut ip: [u8; 16] = [0; 16];



        for i in 0..16 {
            ip[i] = self.inner[index + i]
        }

        Ipv6Addr::from(ip)
    }

    pub fn source(&self) -> Ipv6Addr {
        self.read_ipv6_at(8)
    }

    pub fn destination(&self) -> Ipv6Addr {
        self.read_ipv6_at(24)
    }

    pub fn payload(&self) -> Bytes {
        self.inner.slice(40, 40 + self.payload_length() as usize)
    }

    pub fn from_bytes(data: Bytes) -> Ipv6Frame {
        Ipv6Frame { inner: data }
    }
}
