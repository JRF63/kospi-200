use crate::{ETHER_TYPE_IPV4, ETHER_TYPE_IPV6, IPV6_HEADER_SIZE, convert_with_offset};

pub struct IpPacket<'a> {
    pub protocol: u8,
    pub data: &'a [u8],
}

impl<'a> IpPacket<'a> {
    pub fn new(ether_type: u16, data: &'a [u8]) -> Option<Self> {
        let (protocol, ip_header_size) = match ether_type {
            ETHER_TYPE_IPV4 => {
                // IPv4 Header (20 bytes minimum)
                // +---------+--------+-----------+-----------------------------------------+
                // | Offset  | Size   | Field     | Description                             |
                // +---------+--------+-----------+-----------------------------------------+
                // | 0       | 1      | ver_ihl   | Version (4) & Header Length (IHL)       |
                // | 1       | 1      | tos       | Type of Service                         |
                // | 2..4    | 2      | total_len | Total length of IP packet               |
                // | 4..6    | 2      | id        | Identification                          |
                // | 6..8    | 2      | flags_off | Flags and Fragment Offset               |
                // | 8       | 1      | ttl       | Time to Live                            |
                // | 9       | 1      | protocol  | Protocol                                |
                // | 10..12  | 2      | checksum  | Header Checksum                         |
                // | 12..16  | 4      | src_ip    | Source IP Address                       |
                // | 16..20  | 4      | dst_ip    | Destination IP Address                  |
                // +---------+--------+-----------+-----------------------------------------+
                let ver_ihl = u8::from_be_bytes(convert_with_offset::<1>(data, 0)?);
                let ihl = ver_ihl & 0b1111;
                let header_size = (ihl as usize) * 4;

                let protocol = u8::from_be_bytes(convert_with_offset::<1>(data, 9)?);

                (protocol, header_size)
            }
            ETHER_TYPE_IPV6 => {
                // IPv6 Header (40 bytes)
                // +---------+--------+-----------+-----------------------------------------+
                // | Offset  | Size   | Field     | Description                             |
                // +---------+--------+-----------+-----------------------------------------+
                // | 0..4    | 4      | ver_tc_fl | Version(6), Traffic Class, Flow Label   |
                // | 4..6    | 2      | payload_ln| Payload Length (UDP Header + Data)      |
                // | 6       | 1      | next_hdr  | Next Header                             |
                // | 7       | 1      | hop_limit | Hop Limit (TTL)                         |
                // | 8..24   | 16     | src_ip    | 128-bit Source Address                  |
                // | 24..40  | 16     | dst_ip    | 128-bit Destination Address             |
                // +---------+--------+-----------+-----------------------------------------+
                let protocol = u8::from_be_bytes(convert_with_offset::<1>(data, 6)?);

                (protocol, IPV6_HEADER_SIZE)
            }
            _ => {
                // Unknown EtherType
                return None;
            }
        };

        Some(Self {
            protocol,
            data: data.get(ip_header_size..)?,
        })
    }
}

#[test]
fn test_ip_parsing() {
    use crate::{
        ethernet::EthernetPacket,
        pcap::{PcapIterator, PcapPacket},
    };

    let mmap = crate::open_mmaped_file("mdf-kospi200.20110216-0.pcap").unwrap();
    let iterator = PcapIterator::new(&mmap);

    assert_eq!(
        iterator
            .filter_map(|p| {
                let PcapPacket { data, .. } = p;
                let EthernetPacket { ether_type, data } = EthernetPacket::new(data)?;
                IpPacket::new(ether_type, data)
            })
            .count(),
        21257
    );
}
