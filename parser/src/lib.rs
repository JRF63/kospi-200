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
    quote::{QuoteIterator, Quote, SortedQuoteIteratorBuckets, SortedQuoteIteratorHeap},
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
