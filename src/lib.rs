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

pub const GLOBAL_HEADER_SIZE: usize = 24;
pub const PACKET_HEADER_SIZE: usize = 16;
pub const ETHERNET_HEADER_SIZE: usize = 14;
pub const IPV4_MIN_HEADER_SIZE: usize = 20;
pub const IPV6_HEADER_SIZE: usize = 40;
pub const UDP_HEADER_SIZE: usize = 8;
pub const QUOTE_PACKET_SIZE: usize = 215;

pub const ETHER_TYPE_IPV4: u16 = 0x0800;
pub const ETHER_TYPE_IPV6: u16 = 0x86DD;
pub const PROTOCOL_NUMBER_UDP: u8 = 0x11;

/// mmap's a file to avoid loading it all into memory.
#[inline]
pub fn open_mmaped_file<P>(path: P) -> std::io::Result<Mmap>
where
    P: AsRef<Path>,
{
    let file = File::open(path)?;

    // SAFETY: Safe assuming no other process modifies the underlying file
    let mmap = unsafe { Mmap::map(&file)? };

    mmap.advise(memmap2::Advice::Sequential)?;

    Ok(mmap)
}

/// Creates a quote iterator from a raw PCAP iterator.
#[inline]
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
                15515 | 15516 => QuotePacket::new(seq_num, pkt_time, data),
                _ => None, // Reject packets not on ports 15515 and 15516
            }
        } else {
            None
        }
    })
}
