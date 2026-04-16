mod ethernet;
mod ip;
mod pcap;
mod quote;
mod time;
mod udp;

use memmap2::Mmap;
use std::{fs::File, path::Path};

pub use self::{
    ethernet::EthernetPacket,
    ip::IpPacket,
    pcap::{PcapIterator, PcapPacket},
    quote::QuotePacket,
    time::Timestamp,
    udp::UdpPacket,
};

const GLOBAL_HEADER_SIZE: usize = 24;
const PACKET_HEADER_SIZE: usize = 16;
const ETHERNET_HEADER_SIZE: usize = 14;
const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV6_HEADER_SIZE: usize = 40;
const UDP_HEADER_SIZE: usize = 8;
const QUOTE_PACKET_SIZE: usize = 215;

const ETHER_TYPE_IPV4: u16 = 0x0800;
const ETHER_TYPE_IPV6: u16 = 0x86DD;
const PROTOCOL_NUMBER_UDP: u8 = 0x11;

pub fn open_mmaped_file<P>(path: P) -> std::io::Result<Mmap>
where
    P: AsRef<Path>,
{
    let file = File::open(path)?;

    // SAFETY: Safe assuming no other process modifies the underlying file
    unsafe { Mmap::map(&file) }
}

pub fn build_quote_iterator<'a>(
    pcap_iterator: PcapIterator<'a>,
) -> impl Iterator<Item = QuotePacket<'a>> {
    pcap_iterator.enumerate().filter_map(|(seq_num, p)| {
        let PcapPacket { pkt_time, data } = p;
        let EthernetPacket { ether_type, data } = EthernetPacket::new(data)?;
        let IpPacket { protocol, data } = IpPacket::new(ether_type, data)?;

        // Only accept UDP packets
        if protocol == PROTOCOL_NUMBER_UDP {
            let UdpPacket { dst_port, data } = UdpPacket::new(data)?;

            match dst_port {
                15515..=15516 => QuotePacket::new(seq_num, pkt_time, data),
                _ => None, // Reject packets not on ports 15515 and 15516
            }
        } else {
            None
        }
    })
}
