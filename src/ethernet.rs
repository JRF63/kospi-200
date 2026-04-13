use crate::{ETHERNET_HEADER_SIZE, convert_with_offset};

pub struct EthernetPacket<'a> {
    pub ether_type: u16,
    pub data: &'a [u8],
}

impl<'a> EthernetPacket<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        // Ethernet Header (14 bytes)
        // +---------+--------+-----------+-----------------------------------------+
        // | Indices | Size   | Field     | Value / Description                     |
        // +---------+--------+-----------+-----------------------------------------+
        // | 0..6    | 6      | dst_mac   | Destination MAC                         |
        // | 6..12   | 6      | src_mac   | Source MAC                              |
        // | 12..14  | 2      | type      | EtherType                               |
        // +---------+--------+-----------+-----------------------------------------+
        let ether_type = u16::from_be_bytes(convert_with_offset::<2>(data, 12)?);

        Some(Self {
            ether_type,
            data: data.get(ETHERNET_HEADER_SIZE..)?,
        })
    }
}

#[test]
fn test_ethernet_parsing() {
    use crate::pcap::{PcapIterator, PcapPacket};

    let mmap = crate::open_mmaped_file("mdf-kospi200.20110216-0.pcap").unwrap();
    let iterator = PcapIterator::new(&mmap);

    assert_eq!(
        iterator
            .filter_map(|p| {
                let PcapPacket { data, .. } = p;
                EthernetPacket::new(data)
            })
            .count(),
        21273
    );
}
