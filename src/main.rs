use memmap2::Mmap;
use std::fs::File;
use std::iter::Iterator;

const GLOBAL_HEADER_SIZE: usize = 24;
const PACKET_HEADER_SIZE: usize = 16;
const ETHERNET_HEADER_SIZE: usize = 14;
const IPV4_HEADER_SIZE: usize = 20;
const UDP_HEADER_SIZE: usize = 8;
const NETWORK_HEADER_SIZE: usize = ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE + UDP_HEADER_SIZE;

struct Quote {}

struct QuoteIterator<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> QuoteIterator<'a> {
    fn new(data: &'a [u8]) -> QuoteIterator<'a> {
        QuoteIterator {
            data,
            offset: GLOBAL_HEADER_SIZE, // Skip global header
        }
    }
}

impl<'a> Iterator for QuoteIterator<'a> {
    type Item = Quote;

    fn next(&mut self) -> Option<Self::Item> {
        while self.offset < self.data.len() {
            //  PCAP Packet Header (16 bytes total)
            //  +---------+--------+----------+------------------------------------------+
            //  | Indices | Size   | Field    | Description                              |
            //  +---------+--------+----------+------------------------------------------+
            //  | 0..4    | 4      | ts_sec   | Timestamp: Seconds since Epoch           |
            //  | 4..8    | 4      | ts_usec  | Timestamp: Microseconds                  |
            //  | 8..12   | 4      | cap_len  | Number of bytes actually saved in file   |
            //  | 12..16  | 4      | orig_len | Original length of packet on the wire    |
            //  +---------+--------+----------+------------------------------------------+
            let pkt_header: &[u8; PACKET_HEADER_SIZE] = {
                let header_bytes: &[u8] = self
                    .data
                    .get(self.offset..(self.offset + PACKET_HEADER_SIZE))?; // Returns `None` if slicing fails

                // SAFETY: The byte slice is exactly `PACKET_HEADER_SIZE` long
                unsafe { header_bytes.try_into().unwrap_unchecked() }
            };
            // `unwrap` here should be optimized out since `pkt_header` is a `&[u8; 16]`
            let cap_len = u32::from_le_bytes(pkt_header[8..12].try_into().unwrap()) as usize;

            let payload_start = self.offset + PACKET_HEADER_SIZE + NETWORK_HEADER_SIZE;
            let payload_end = self.offset + PACKET_HEADER_SIZE + cap_len;
            let payload = self.data.get(payload_start..payload_end)?; // Return `None` if not enough data

            // Check if a quote packet
            let result = if payload.starts_with(b"B6034") {
                //   UDP Header (8 bytes total) - Network Byte Order (Big-Endian)
                //   +---------+--------+-----------+-----------------------------------------+
                //   | Indices | Size   | Field     | Description                             |
                //   +---------+--------+-----------+-----------------------------------------+
                //   | 0..2    | 2      | src_port  | Source Port                             |
                //   | 2..4    | 2      | dst_port  | Destination Port                        |
                //   | 4..6    | 2      | length    | Total UDP length                        |
                //   | 6..8    | 2      | checksum  | Checksum                                |
                //   +---------+--------+-----------+-----------------------------------------+
                let dst_port = u16::from_be_bytes({
                    let dst_port_start = self.offset
                        + PACKET_HEADER_SIZE
                        + ETHERNET_HEADER_SIZE
                        + IPV4_HEADER_SIZE
                        + 2;

                    let udp_header_bytes: &[u8] =
                        self.data.get(dst_port_start..(dst_port_start + 2))?;

                    // SAFETY: This slice is exactly 2 units long
                    unsafe { udp_header_bytes.try_into().unwrap_unchecked() }
                });

                if let 15515..=15516 = dst_port {
                    Some(Quote {})
                } else {
                    None
                }
            } else {
                None
            };

            // Advance to the next packet
            self.offset += PACKET_HEADER_SIZE + cap_len;

            if result.is_some() {
                return result;
            }
        }
        None
    }
}

fn main() -> std::io::Result<()> {
    const FILENAME: &str = "mdf-kospi200.20110216-0.pcap";

    let file = File::open(FILENAME)?;
    let mmap = unsafe { Mmap::map(&file)? };

    let foo = QuoteIterator::new(&mmap);

    // 1. Extract the Quote Accept Time (last 8 bytes of message)
    // 2. Push to BinaryHeap for reordering

    assert_eq!(16004, foo.count());

    Ok(())
}

#[cfg(test)]
fn test_pcap_header(data: &[u8]) {
    let (val, data) = data.split_at(4);
    println!(
        "Magic number: 0x{:x}",
        u32::from_le_bytes(val.try_into().unwrap())
    );

    let (val, data) = data.split_at(2);
    println!(
        "Major version: {}",
        u16::from_le_bytes(val.try_into().unwrap())
    );

    let (val, data) = data.split_at(2);
    println!(
        "Minor version: {}",
        u16::from_le_bytes(val.try_into().unwrap())
    );

    let (val, data) = data.split_at(4);
    println!("Thiszone: {}", u32::from_le_bytes(val.try_into().unwrap()));

    let (val, data) = data.split_at(4);
    println!("Sigfigs: {}", u32::from_le_bytes(val.try_into().unwrap()));

    let (val, data) = data.split_at(4);
    println!("Snaplen: {}", u32::from_le_bytes(val.try_into().unwrap()));

    let (val, _) = data.split_at(4);
    println!("Network: {}", u32::from_le_bytes(val.try_into().unwrap()));
}
