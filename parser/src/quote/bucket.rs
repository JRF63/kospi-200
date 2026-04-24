use crate::{
    QUOTE_PACKET_SIZE,
    pcap::PcapIterator,
    quote::{QuoteIterator, QuotePacket},
    time::Timestamp,
};
use smallvec::SmallVec;
use std::iter::FusedIterator;

// Need at least 300 (3 seconds + centisecond resolution) but use the nearest power of two to make
// modulo calculations faster
const BUCKET_LEN: usize = 512;

#[derive(Debug, Default, Clone)]
struct Bucket<'a> {
    // The array length 4 is arbitrary and should be tuned to the dataset
    vec: SmallVec<[BucketedQuotePacket<'a>; 4]>,

    // These two should all be the same for all quotes inside `vec` above
    accept_time: Option<Timestamp>,
    midnight_at_timezone: Option<Timestamp>,
}

// `accept_time` and `midnight_at_timezone` are stripped out. `seq_num` isn't necessary for stable
// sorting
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BucketedQuotePacket<'a> {
    pkt_time: Timestamp,
    data: &'a [u8; QUOTE_PACKET_SIZE],
}

impl<'a> Bucket<'a> {
    fn remove(&mut self, index: usize) -> QuotePacket<'a> {
        let BucketedQuotePacket { pkt_time, data } = self.vec.remove(index);

        // SAFETY: `accept_time` and `midnight_at_timezone` are always initialized when pushing to
        // `vec`
        unsafe {
            QuotePacket {
                seq_num: 0,
                pkt_time,
                accept_time: self.accept_time.unwrap_unchecked(),
                midnight_at_timezone: self.midnight_at_timezone.unwrap_unchecked(),
                data,
            }
        }
    }
    fn push(&mut self, quote: QuotePacket<'a>) {
        let QuotePacket {
            seq_num: _,
            pkt_time,
            accept_time,
            midnight_at_timezone,
            data,
        } = quote;
        self.accept_time = Some(accept_time);
        self.midnight_at_timezone = Some(midnight_at_timezone);

        self.vec.push(BucketedQuotePacket { pkt_time, data });
    }
    fn is_empty(&self) -> bool {
        self.vec.is_empty()
    }
}

// Bucket sorting - O(N)
pub struct SortedQuoteIteratorBuckets<'a> {
    quote_iterator: QuoteIterator<'a>,
    buckets: Box<[Bucket<'a>; BUCKET_LEN]>,
    earliest_accept_time: Option<Timestamp>,
    emit_idx: Option<usize>,
    safe_idx: Option<usize>,
    last_idx: Option<usize>,
}

impl<'a> SortedQuoteIteratorBuckets<'a> {
    pub fn new(pcap_iterator: PcapIterator<'a>) -> Self {
        Self {
            quote_iterator: QuoteIterator::new(pcap_iterator),
            buckets: vec![Default::default(); BUCKET_LEN].try_into().unwrap(),
            earliest_accept_time: None,
            emit_idx: None,
            safe_idx: None,
            last_idx: None,
        }
    }

    // Try to return one packet from the buckets
    fn try_emit_packet<'b>(
        emit_idx: &mut usize,
        safe_idx: usize,
        buckets: &mut Box<[Bucket<'b>; BUCKET_LEN]>,
    ) -> Option<QuotePacket<'b>> {
        let mut next_idx = *emit_idx;
        loop {
            let bucket = buckets.get_mut(next_idx).unwrap();
            if !bucket.is_empty() {
                *emit_idx = next_idx;

                // This is O(N) so must keep the size of the buckets small
                let quote = bucket.remove(0);

                return Some(quote);
            }
            if next_idx == safe_idx {
                break;
            }
            next_idx = (next_idx + 1) % BUCKET_LEN;
        }
        None
    }

    // Return a packet older than 3 seconds
    fn try_emit_elapsed_packet<'b>(
        emit_idx: &mut Option<usize>,
        safe_idx: Option<usize>,
        buckets: &mut Box<[Bucket<'b>; BUCKET_LEN]>,
    ) -> Option<QuotePacket<'b>> {
        if let Some(emit_idx) = emit_idx.as_mut()
            && let Some(safe_idx) = safe_idx
        {
            // Check if `safe_idx` >= `emit_idx` using the half-range rule
            let gt_or_eq = {
                let diff = safe_idx.wrapping_sub(*emit_idx) % BUCKET_LEN;

                // diff >= 0 && diff <= mid
                (0..=(BUCKET_LEN / 2)).contains(&diff)
            };

            if gt_or_eq && let Some(quote) = Self::try_emit_packet(emit_idx, safe_idx, buckets) {
                return Some(quote);
            }
        }

        None
    }
}

impl<'a> FusedIterator for SortedQuoteIteratorBuckets<'a> {}

impl<'a> Iterator for SortedQuoteIteratorBuckets<'a> {
    type Item = QuotePacket<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // Greedily try to emit a packet. This prevents the `SmallVec`s from allocating by keeping
        // them small.
        if let Some(quote) =
            Self::try_emit_elapsed_packet(&mut self.emit_idx, self.safe_idx, &mut self.buckets)
        {
            return Some(quote);
        }

        const THREE_SECONDS: Timestamp = Timestamp::from_secs_and_nanos(3, 0);

        for quote in self.quote_iterator.by_ref() {
            let current_time = quote.pkt_time;

            let safe_idx = {
                let safe_time = current_time - THREE_SECONDS;
                safe_time.timestamp_centiseconds() as usize % BUCKET_LEN
            };
            self.safe_idx = Some(safe_idx);

            let idx = quote.accept_time.timestamp_centiseconds() as usize % BUCKET_LEN;

            // Initialize the index of the bucket that will be emitted first
            if self.emit_idx.is_none() {
                let accept_time = quote.accept_time;
                let earliest_accept_time = match self.earliest_accept_time.as_mut() {
                    Some(earliest_accept_time) => {
                        if accept_time < *earliest_accept_time {
                            *earliest_accept_time = accept_time;
                        }
                        *earliest_accept_time
                    }
                    None => {
                        let earliest_accept_time = accept_time;
                        self.earliest_accept_time = Some(earliest_accept_time);
                        earliest_accept_time
                    }
                };

                if current_time - earliest_accept_time >= THREE_SECONDS {
                    let emit_idx =
                        earliest_accept_time.timestamp_centiseconds() as usize % BUCKET_LEN;
                    self.emit_idx = Some(emit_idx);
                }
            }

            self.buckets[idx].push(quote);

            if let Some(quote) =
                Self::try_emit_elapsed_packet(&mut self.emit_idx, self.safe_idx, &mut self.buckets)
            {
                return Some(quote);
            }
        }

        // Drain the buckets
        if let Some(emit_idx) = self.emit_idx.as_mut() {
            match self.last_idx {
                Some(last_idx) => {
                    if let Some(quote) =
                        Self::try_emit_packet(emit_idx, last_idx, &mut self.buckets)
                    {
                        return Some(quote);
                    }
                }
                None => {
                    let last_idx = match *emit_idx {
                        0 => BUCKET_LEN - 1,
                        i => i - 1,
                    };
                    self.last_idx = Some(last_idx);
                    if let Some(quote) =
                        Self::try_emit_packet(emit_idx, last_idx, &mut self.buckets)
                    {
                        return Some(quote);
                    }
                }
            }
        }

        None
    }
}
