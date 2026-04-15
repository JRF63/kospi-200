use crate::{GLOBAL_HEADER_SIZE, PACKET_HEADER_SIZE};

pub struct PcapPacket<'a> {
    pub pkt_time: i64,
    pub data: &'a [u8],
}

pub struct PcapIterator<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> PcapIterator<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        // TODO: Return a Result/Option instead of using asserts

        assert_eq!(
            u32::from_le_bytes(data[0..4].try_into().unwrap()),
            0xa1b2c3d4,
            "Can only parse PCAP files that were written in little-endian and have timestamps in \
             microseconds"
        );

        assert_eq!(
            u32::from_le_bytes(data[20..24].try_into().unwrap()),
            1,
            "Can only parse PCAP files that use Ethernet"
        );

        Self {
            data,
            offset: GLOBAL_HEADER_SIZE, // Skip global header
        }
    }
}

impl<'a> Iterator for PcapIterator<'a> {
    type Item = PcapPacket<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // PCAP Packet Header (16 bytes)
        // +---------+--------+----------+------------------------------------------+
        // | Indices | Size   | Field    | Description                              |
        // +---------+--------+----------+------------------------------------------+
        // | 0..4    | 4      | ts_sec   | Timestamp: Seconds since Epoch           |
        // | 4..8    | 4      | ts_usec  | Timestamp: Microseconds                  |
        // | 8..12   | 4      | cap_len  | Number of bytes actually saved in file   |
        // | 12..16  | 4      | orig_len | Original length of packet on the wire    |
        // +---------+--------+----------+------------------------------------------+
        let pkt_header: &[u8; PACKET_HEADER_SIZE] = {
            let header_bytes: &[u8] = self.data.get(self.offset..)?;
            header_bytes.first_chunk::<_>()?
        };

        // The following `unwrap`s should be optimized out since `pkt_header` is a `&[u8; 16]`
        let ts_sec = u32::from_le_bytes(pkt_header[0..4].try_into().unwrap());
        let ts_usec = u32::from_le_bytes(pkt_header[4..8].try_into().unwrap());
        let cap_len = u32::from_le_bytes(pkt_header[8..12].try_into().unwrap()) as usize;

        let pkt_time = (ts_sec as i64 * 1_000_000) + (ts_usec as i64);

        let data = {
            let start = self.offset + PACKET_HEADER_SIZE;
            let end = self.offset + PACKET_HEADER_SIZE + cap_len;
            self.data.get(start..end)? // Stops the iterator if not enough data
        };

        // Advance to the next PCAP packet
        self.offset += PACKET_HEADER_SIZE + cap_len;

        Some(PcapPacket { pkt_time, data })
    }
}

#[test]
fn test_pcap_parsing() {
    let mmap = crate::open_mmaped_file("mdf-kospi200.20110216-0.pcap").unwrap();
    let iterator = PcapIterator::new(&mmap);

    assert_eq!(iterator.count(), 21273);
}
