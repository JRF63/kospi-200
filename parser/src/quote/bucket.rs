use crate::{
    quote::{Quote, QuotePacket},
    time::{NANOS_PER_CENT, Timestamp},
};
use std::{collections::VecDeque, iter::FusedIterator};

// Need at least 300 (3 seconds + centisecond resolution) but use the next power of two to make
// modulo calculations faster
const NUM_BUCKETS: usize = 512;

const EPOCH: Timestamp = Timestamp::from_secs_and_nanos(0, 0);
const THREE_SECONDS: Timestamp = Timestamp::from_secs_and_nanos(3, 0);
const CENTISECOND: Timestamp = Timestamp::from_secs_and_nanos(0, NANOS_PER_CENT);

#[derive(Debug, Clone)]
struct Bucket<'a> {
    deque: VecDeque<QuotePacket<'a>>,

    // These two should all be the same for all quotes inside `vec` above
    accept_time: Timestamp,
    midnight_at_timezone: Timestamp,
}

impl<'a> Bucket<'a> {
    fn with_capacity(bucket_capacity: usize) -> Self {
        Self {
            deque: VecDeque::with_capacity(bucket_capacity),
            accept_time: EPOCH,
            midnight_at_timezone: EPOCH,
        }
    }

    fn pop(&mut self) -> Option<Quote<'a>> {
        self.deque.pop_back().map(|p| {
            let QuotePacket { pkt_time, data } = p;
            Quote {
                pkt_time,
                accept_time: self.accept_time,
                midnight_at_timezone: self.midnight_at_timezone,
                data,
            }
        })
    }

    fn push(
        &mut self,
        quote_packet: QuotePacket<'a>,
        accept_time: Timestamp,
        midnight_at_timezone: Timestamp,
    ) {
        self.accept_time = accept_time;
        self.midnight_at_timezone = midnight_at_timezone;

        // Insert to the front to maintain a stable sort
        self.deque.push_front(quote_packet);
    }
}

// Bucket sorting - O(N)
pub struct SortedQuoteIteratorBuckets<'a, T> {
    quote_iterator: T,
    buckets: [Bucket<'a>; NUM_BUCKETS],
    drain_bucket_idx: Option<usize>,
    current_position: Option<(usize, Timestamp)>,
    earliest_accept_time: Timestamp,
    state: State<'a>,
}

struct PendingPush<'a> {
    index: usize,
    quote_packet: QuotePacket<'a>,
    accept_time: Timestamp,
    midnight_at_timezone: Timestamp,
}

enum State<'a> {
    DrainIterator,
    EmitQuote(Timestamp, PendingPush<'a>),
    DrainBuckets(Timestamp),
}

impl<'a, T> SortedQuoteIteratorBuckets<'a, T>
where
    T: Iterator<Item = QuotePacket<'a>>,
{
    pub fn with_capacity(quote_iterator: T, bucket_capacity: usize) -> Self {
        Self {
            quote_iterator,
            buckets: std::array::from_fn(|_| Bucket::with_capacity(bucket_capacity)),
            drain_bucket_idx: None,

            // Set to the largest possible timestamp so it gets immediately overwritten by the first
            // packet
            earliest_accept_time: Timestamp::from_secs_and_nanos(0, i64::MAX),

            current_position: None,
            state: State::DrainIterator,
        }
    }
}

impl<'a, T> SortedQuoteIteratorBuckets<'a, T> {
    // Return the index of the oldest non-empty bucket and also return the oldest quote in that
    // bucket.
    fn find_non_empty_bucket<'b>(
        current_position: &mut (usize, Timestamp),
        expired_timestamp: Timestamp,
        buckets: &mut [Bucket<'b>; NUM_BUCKETS],
    ) -> Option<(usize, Quote<'b>)> {
        loop {
            if current_position.1 <= expired_timestamp {
                // SAFETY: `current_position.0` is calculated module `NUM_BUCKETS`
                let bucket = unsafe { buckets.get_unchecked_mut(current_position.0) };

                // Debug check the accept time incrementing logic
                debug_assert!(if !bucket.deque.is_empty() {
                    current_position.1 == bucket.accept_time
                } else {
                    true
                });

                let current_index = current_position.0;
                *current_position = (
                    (current_position.0 + 1) % NUM_BUCKETS,
                    current_position.1 + CENTISECOND, // Buckets have centisecond granularity
                );
                if let Some(quote) = bucket.pop() {
                    return Some((current_index, quote));
                }
            } else {
                break;
            }
        }
        None
    }
}

impl<'a, T> FusedIterator for SortedQuoteIteratorBuckets<'a, T> where
    T: Iterator<Item = QuotePacket<'a>>
{
}

impl<'a, T> Iterator for SortedQuoteIteratorBuckets<'a, T>
where
    T: Iterator<Item = QuotePacket<'a>>,
{
    type Item = Quote<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // Return the packets from the current bucket. If one packet was returned and
        // `self.drain_bucket_idx` was set to `Some`, then all the other packets in the same bucket
        // must also be older than 3 seconds.
        if let Some(index) = self.drain_bucket_idx {
            // SAFETY: Indices returned by `find_non_empty_bucket` should always be in range
            let bucket = unsafe { self.buckets.get_unchecked_mut(index) };

            if let Some(quote) = bucket.pop() {
                return Some(quote);
            }
        }
        self.drain_bucket_idx = None;

        'outer: loop {
            match self.state {
                State::DrainIterator => {
                    for quote_packet in self.quote_iterator.by_ref() {
                        // TODO: Try leaving calcs in centiseconds
                        let Quote {
                            pkt_time,
                            accept_time,
                            midnight_at_timezone,
                            data,
                        } = quote_packet.into_quote();

                        // Initialize the index of the bucket that will be emitted first
                        if self.current_position.is_none() {
                            if accept_time < self.earliest_accept_time {
                                self.earliest_accept_time = accept_time;
                            }

                            if pkt_time - self.earliest_accept_time >= THREE_SECONDS {
                                let earliest_index =
                                    self.earliest_accept_time.timestamp_centiseconds() as usize
                                        % NUM_BUCKETS;
                                self.current_position =
                                    Some((earliest_index, self.earliest_accept_time));
                            }
                        }

                        let expired_timestamp = pkt_time - THREE_SECONDS;

                        let pending_push = PendingPush {
                            index: accept_time.timestamp_centiseconds() as usize % NUM_BUCKETS,
                            quote_packet: QuotePacket { pkt_time, data },
                            accept_time,
                            midnight_at_timezone,
                        };

                        // Same logic as `State::EmitQuote` below but inlined here for performance.
                        // This if-else is equivalent to:
                        // ```
                        // self.state = State::EmitQuote(expired_timestamp, pending_push);
                        // continue 'outer;
                        // ```
                        if let Some(current_position) = self.current_position.as_mut()
                            && let Some((drain_bucket_idx, quote)) = Self::find_non_empty_bucket(
                                current_position,
                                expired_timestamp,
                                &mut self.buckets,
                            )
                        {
                            self.state = State::EmitQuote(expired_timestamp, pending_push);
                            self.drain_bucket_idx = Some(drain_bucket_idx);
                            return Some(quote);
                        } else {
                            let PendingPush {
                                index,
                                quote_packet,
                                accept_time,
                                midnight_at_timezone,
                            } = pending_push;

                            // SAFETY: `index` was calculated modulo `NUM_BUCKETS`
                            let bucket = unsafe { self.buckets.get_unchecked_mut(index) };
                            bucket.push(quote_packet, accept_time, midnight_at_timezone);
                        }
                    }

                    let current_timestamp = match self.current_position {
                        Some((_, timestamp)) => timestamp,
                        None => {
                            // If `None`, that implies all of the packets are younger than 3
                            // seconds. `self.quote_iterator` is completely drained but the packets
                            // still need to be emptied from the buckets.
                            let index = self.earliest_accept_time.timestamp_centiseconds() as usize
                                % NUM_BUCKETS;
                            self.current_position = Some((index, self.earliest_accept_time));
                            self.earliest_accept_time
                        }
                    };

                    // This causes a full sweep of the buckets. Last accept time + 3 seconds is more
                    // efficient but that requires extra bookkeeping on the hot path.
                    let final_timestamp =
                        current_timestamp + CENTISECOND * (NUM_BUCKETS - 1) as i64;

                    self.state = State::DrainBuckets(final_timestamp);
                }
                State::EmitQuote(expired_timestamp, _) => {
                    // Drain all expired packets
                    if let Some(current_position) = self.current_position.as_mut()
                        && let Some((drain_bucket_idx, quote)) = Self::find_non_empty_bucket(
                            current_position,
                            expired_timestamp,
                            &mut self.buckets,
                        )
                    {
                        self.drain_bucket_idx = Some(drain_bucket_idx);
                        return Some(quote);

                    // The earliest that the pending packet could be is (T - 3) seconds. We first
                    // return all packets <= (T - 3) seconds on the if part of this if-else before
                    // adding the pending packet to the buckets in this else.
                    } else {
                        // `self.state` is now `State::DrainIterator` and `old_state` contains the
                        // previous state
                        let old_state = std::mem::replace(&mut self.state, State::DrainIterator);

                        let State::EmitQuote(_, pending_push) = old_state else {
                            // SAFETY: The previous state should be same as what was matched in the
                            // current branch
                            unsafe { std::hint::unreachable_unchecked() };
                        };

                        let PendingPush {
                            index,
                            quote_packet,
                            accept_time,
                            midnight_at_timezone,
                        } = pending_push;

                        // SAFETY: `index` was calculated modulo `NUM_BUCKETS`
                        let bucket = unsafe { self.buckets.get_unchecked_mut(index) };
                        bucket.push(quote_packet, accept_time, midnight_at_timezone);

                        continue 'outer;
                    }
                }
                State::DrainBuckets(last_idx) => {
                    // Drain the rest of the packets from the buckets
                    if let Some(current_position) = self.current_position.as_mut()
                        && let Some((drain_bucket_idx, quote)) = Self::find_non_empty_bucket(
                            current_position,
                            last_idx,
                            &mut self.buckets,
                        )
                    {
                        self.drain_bucket_idx = Some(drain_bucket_idx);
                        return Some(quote);
                    }
                    break 'outer;
                }
            }
        }

        None
    }
}
