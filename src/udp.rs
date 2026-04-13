use crate::{UDP_HEADER_SIZE, convert_with_offset};

pub struct UdpPacket<'a> {
    pub dst_port: u16,
    pub data: &'a [u8],
}

impl<'a> UdpPacket<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        // UDP Header (8 bytes)
        // +---------+--------+-----------+-----------------------------------------+
        // | Indices | Size   | Field     | Description                             |
        // +---------+--------+-----------+-----------------------------------------+
        // | 0..2    | 2      | src_port  | Source Port                             |
        // | 2..4    | 2      | dst_port  | Destination Port                        |
        // | 4..6    | 2      | length    | Total UDP length                        |
        // | 6..8    | 2      | checksum  | Checksum                                |
        // +---------+--------+-----------+-----------------------------------------+
        let dst_port = u16::from_be_bytes(convert_with_offset::<2>(data, 2)?);

        Some(Self {
            dst_port,
            data: data.get(UDP_HEADER_SIZE..)?,
        })
    }
}

#[test]
fn test_udp_parsing() {
    use crate::{
        PROTOCOL_NUMBER_UDP,
        ethernet::EthernetPacket,
        ip::IpPacket,
        pcap::{PcapIterator, PcapPacket},
    };

    let mmap = crate::open_mmaped_file("mdf-kospi200.20110216-0.pcap").unwrap();
    let iterator = PcapIterator::new(&mmap);

    assert_eq!(
        iterator
            .filter_map(|p| {
                let PcapPacket { data, .. } = p;
                let EthernetPacket { ether_type, data } = EthernetPacket::new(data)?;
                let IpPacket { protocol, data } = IpPacket::new(ether_type, data)?;

                if protocol == PROTOCOL_NUMBER_UDP {
                    UdpPacket::new(data)
                } else {
                    None
                }
            })
            .count(),
        21247
    );
}
