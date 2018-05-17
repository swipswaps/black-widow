use std::net::{Ipv4Addr, Ipv6Addr};
use std::fmt::{Debug, Formatter};
use std::fmt;
use bytes::Bytes;

macro_rules! ube {
    ($size:ident, $from:expr) => {
        $size::from_be($size::from($from))
    };
}

macro_rules! u16 {
    ($arr:expr, $from:expr) => {
        ube!(u16, $arr[$from]) + (ube!(u16, $arr[$from + 1]) >> 8)
    };
}


#[derive(Debug, Hash, Eq, PartialOrd, PartialEq)]
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
        match self.inner[0] >> 5 {
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
        (self.inner[2] & 16) == 8
    }

    pub fn vlan_id(&self) -> u16 {
        (u16::from(self.inner[2] & 15) << 4) + (u16::from(self.inner[3]) >> 4)
    }

    pub fn from_bytes(data: Bytes) -> Option<QTag> {
        assert_eq!(data.len(), 4);

        if u16!(data, 0) << 8 == 0x8100 {
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
        return EtherType(u16!(self.inner, index));
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
        let data = self.inner.slice(self.header_size(), self.inner.len());

        let ether_type = &self.ether_type();

        match ether_type {
            ether_type if ether_type.is_arp_frame() => {
                return EthernetPayload::ARP(ARPFrame::from_bytes(data));
            }

            ether_type if ether_type.is_ipv4_frame() => {
                return EthernetPayload::Ipv4Frame(Ipv4Frame::from_bytes(data));
            }

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

pub struct ARPFrame {
    inner: Bytes,
}

impl ARPFrame {
    pub fn hardware_type(&self) -> u16 {
        u16!(self.inner, 0)
    }

    pub fn protocol_type(&self) -> u16 {
        u16!(self.inner, 2)
    }

    pub fn hardware_address_length(&self) -> u8 {
        self.inner[4]
    }

    pub fn protocol_address_length(&self) -> u8 {
        self.inner[5]
    }

    pub fn operation(&self) -> u16 {
        u16!(self.inner, 6)
    }

    pub fn sender_hardware_address(&self) -> Bytes {
        self.inner.slice(8, (8 + self.hardware_address_length()) as usize)
    }

    pub fn sender_protocol_address(&self) -> Bytes {
        let offset: usize = (self.hardware_address_length() + 8) as usize;
        self.inner.slice(offset, offset + self.protocol_address_length() as usize)
    }

    pub fn target_hardware_address(&self) -> Bytes {
        let hw_len: usize = self.hardware_address_length() as usize;
        let proto_len: usize = self.protocol_address_length() as usize;
        let offset: usize = 8 + hw_len + proto_len;

        self.inner.slice(offset, offset + hw_len)
    }

    pub fn target_protocol_address(&self) -> Bytes {
        let hw_len: usize = self.hardware_address_length() as usize;
        let proto_len: usize = self.protocol_address_length() as usize;
        let offset: usize = 8 + hw_len * 2 + proto_len;

        self.inner.slice(offset, offset + proto_len)
    }

    pub fn from_bytes(data: Bytes) -> ARPFrame {
        ARPFrame { inner: data }
    }
}

impl Debug for ARPFrame {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "ARPFrame {{ hardware_type: {:?}, protocol_type: {:?}, hardware_address_length: {:?}, protocol_address_length: {:?}, sender_hardware_address: {:?}, sender_protocol_address: {:?}, target_hardware_address: {:?}, target_protocol_address: {:?} }}",
            self.hardware_type(),
            self.protocol_type(),
            self.hardware_address_length(),
            self.protocol_address_length(),
            self.sender_hardware_address(),
            self.sender_protocol_address(),
            self.target_hardware_address(),
            self.target_protocol_address(),
        )
    }
}


pub struct Ipv4Frame {
    inner: Bytes,
}

impl Ipv4Frame {
    pub fn version(&self) -> u8 {
        ube!(u8, self.inner[0]) >> 4
    }

    pub fn ihl(&self) -> u8 {
        ube!(u8, self.inner[0]) & 15
    }

    pub fn dscp(&self) -> u8 {
        ube!(u8, self.inner[1]) & 252
    }

    pub fn ecn(&self) -> u8 {
        ube!(u8, self.inner[1]) & 3
    }

    pub fn total_length(&self) -> u16 {
        u16!(self.inner, 2)
    }

    pub fn id(&self) -> u16 {
        u16!(self.inner, 4)
    }

    pub fn flags(&self) -> u8 {
        ube!(u8, self.inner[6]) >> 5
    }

    pub fn fragment_offset(&self) -> u16 {
        u16!(self.inner, 6) & 8191
    }

    pub fn ttl(&self) -> u8 {
        self.inner[8]
    }

    pub fn protocol(&self) -> u8 {
        self.inner[9]
    }

    pub fn header_checksum(&self) -> u16 {
        u16!(self.inner, 10)
    }

    pub fn source(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.inner[12], self.inner[13], self.inner[14], self.inner[15])
    }

    pub fn destination(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.inner[16], self.inner[17], self.inner[18], self.inner[19])
    }

    pub fn options(&self) -> Option<Bytes> {
        if self.ihl() > 5 {
            return Some(self.inner.slice(20, 36));
        }

        None
    }

    pub fn header_size(&self) -> u8 {
        self.ihl() * 5
    }

    pub fn payload(&self) -> Bytes {
        self.inner.slice(self.header_size() as usize, self.total_length() as usize)
    }

    pub fn from_bytes(data: Bytes) -> Ipv4Frame {
        Ipv4Frame {
            inner: data
        }
    }
}

impl Debug for Ipv4Frame {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "Ipv4Frame {{ version: {:?}, ihl: {:?}, dscp: {:?}, ecn: {:?}, total_length: {:?}, id: {:?}, flags: {:?}, fragment_offset: {:?}, ttl: {:?}, protocol: {:?}, header_checksum: {:?}, source: {:?}, destination: {:?}, options: {:?}, payload: {:?} }}",
            self.version(),
            self.ihl(),
            self.dscp(),
            self.ecn(),
            self.total_length(),
            self.id(),
            self.flags(),
            self.fragment_offset(),
            self.ttl(),
            self.protocol(),
            self.header_checksum(),
            self.source(),
            self.destination(),
            self.options(),
            self.payload(),
        )
    }
}

pub struct Ipv6Frame {
    inner: Bytes,
}

impl Ipv6Frame {
    pub fn version(&self) -> u8 {
        self.inner[0] >> 4
    }

    pub fn traffic_class(&self) -> u8 {
        ((ube!(u8,self.inner[0]) & 15) << 4) + ((ube!(u8, self.inner[1]) & 240) >> 4)
    }

    pub fn flow_label(&self) -> u32 {
        ((ube!(u32, self.inner[1]) & 15) << 8) + (ube!(u32, self.inner[2]) << 4) + ube!(u32, self.inner[3])
    }

    pub fn payload_length(&self) -> u16 {
        u16!(self.inner, 4)
    }

    pub fn next_header(&self) -> u8 {
        self.inner[6]
    }

    pub fn hop_limit(&self) -> u8 {
        self.inner[7]
    }

    fn read_ipv6_at(&self, index: usize) -> Ipv6Addr {
        let mut ip: [u8; 16] = [0; 16];

        ip.copy_from_slice(&self.inner[index..index + 16]);

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

impl Debug for Ipv6Frame {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "Ipv6Frame {{ version: {:?}, source: {:?}, destination: {:?}, traffic_class: {:?}, next_header: {:?}, hop_limit: {:?}, payload_length: {:?}, payload: {:?} }}",
            self.version(),
            self.source(),
            self.destination(),
            self.traffic_class(),
            self.next_header(),
            self.hop_limit(),
            self.payload_length(),
            self.payload()
        )
    }
}
