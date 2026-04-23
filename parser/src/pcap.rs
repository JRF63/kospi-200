use crate::{GLOBAL_HEADER_SIZE, PACKET_HEADER_SIZE, time::Timestamp};

pub struct PcapPacket<'a> {
    pub pkt_time: Timestamp,
    pub data: &'a [u8],
}

pub struct PcapIterator<'a> {
    data: &'a [u8],
}

impl<'a> PcapIterator<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        // TODO: Return a Result/Option instead of using asserts

        let (header, data) = data
            .split_at_checked(GLOBAL_HEADER_SIZE)
            .expect("Invalid PCAP file");

        assert_eq!(
            u32::from_le_bytes(*header[0..4].as_array().unwrap()),
            0xa1b2c3d4,
            "Can only parse PCAP files that were written in little-endian and have timestamps in \
             microseconds"
        );

        assert_eq!(
            u32::from_le_bytes(*header[20..24].as_array().unwrap()),
            1,
            "Can only parse PCAP files that use Ethernet"
        );

        Self { data }
    }
}

impl<'a> Iterator for PcapIterator<'a> {
    type Item = PcapPacket<'a>;

    // This is difficult to parallelize because of the need to read `cap_len` from the header
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
        let (header, tail) = self.data.split_at_checked(PACKET_HEADER_SIZE)?;

        // Bounds checking for the following should be optimized out since the len of `header` is
        // known at compile time
        let ts_sec = u32::from_le_bytes(*header[0..4].as_array()?);
        let ts_usec = u32::from_le_bytes(*header[4..8].as_array()?);
        let cap_len = u32::from_le_bytes(*header[8..12].as_array()?);

        // `?` stops the iterator here if there's not enough data
        let (payload, next_data) = tail.split_at_checked(cap_len as usize)?;

        let packet = PcapPacket {
            pkt_time: Timestamp::from_secs_and_nanos(ts_sec as i64, ts_usec as i64 * 1000),
            data: payload,
        };

        // Advance to the next PCAP packet
        self.data = next_data;

        Some(packet)
    }
}

#[test]
fn test_pcap_parsing() {
    let mmap = crate::open_mmaped_file("../dataset/mdf-kospi200.20110216-0.pcap").unwrap();
    let iterator = PcapIterator::new(&mmap);

    assert_eq!(iterator.count(), 21273);
}
