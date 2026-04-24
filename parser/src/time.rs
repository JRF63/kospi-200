const NANOS_PER_HOUR: i64 = 3600 * NANOS_PER_SEC;
const NANOS_PER_MIN: i64 = 60 * NANOS_PER_SEC;
const NANOS_PER_SEC: i64 = 1_000_000_000;
const NANOS_PER_CENT: i64 = NANOS_PER_SEC / 100; // Nanos per centisecond
const NANOS_PER_DAY: i64 = 24 * NANOS_PER_HOUR;

// Nanoseconds after UNIX epoch
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(i64);

impl std::ops::Add for Timestamp {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl std::ops::Sub for Timestamp {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl Timestamp {
    pub const TIMEZONE_KST: i64 = 9 * NANOS_PER_HOUR; // KRX is GMT +9

    pub const fn from_secs_and_nanos(secs: i64, nsecs: i64) -> Self {
        Self(secs * NANOS_PER_SEC + nsecs)
    }

    pub const fn timestamp_centiseconds(&self) -> i64 {
        self.0 / NANOS_PER_CENT
    }

    /// Convert `bytes` in the ASCII HHMMSSuu format to the number of nanoseconds after midnight
    pub fn hhmmssuu_to_midnight_delta(bytes: &[u8; 8]) -> Self {
        let [hour, min, sec, cent] = Timestamp::parse_hhmmssuu(bytes);

        let day_nanos = hour * NANOS_PER_HOUR
            + min * NANOS_PER_MIN
            + sec * NANOS_PER_SEC
            + cent * NANOS_PER_CENT;
        Self(day_nanos)
    }

    pub fn parse_hhmmssuu(bytes: &[u8; 8]) -> [i64; 4] {
        // Read everything into a u64
        let val = u64::from_le_bytes(*bytes);

        // Subtract ASCII '0' from all 8 bytes simultaneously
        let digits = val - 0x3030303030303030;

        // NOTE: Multiplying by 10 simultaneously is slower
        let hour = (digits & 0xFF) * 10 + ((digits >> 8) & 0xFF);
        let min = ((digits >> 16) & 0xFF) * 10 + ((digits >> 24) & 0xFF);
        let sec = ((digits >> 32) & 0xFF) * 10 + ((digits >> 40) & 0xFF);
        let cent = ((digits >> 48) & 0xFF) * 10 + ((digits >> 56) & 0xFF);

        [hour as i64, min as i64, sec as i64, cent as i64]
    }

    /// Returns the midnight timestamp at the given timezone
    pub fn get_midnight_at_timezone(&self, tz_offset: i64) -> Self {
        let time_at_timezone = self.0 + tz_offset;
        let days_since_epoch = time_at_timezone / NANOS_PER_DAY;
        let nanos_midnight = days_since_epoch * NANOS_PER_DAY;
        Self(nanos_midnight - tz_offset)
    }

    /// Convert into the HHMMSSuu format given the midnight timestamp
    pub fn format_hhmmssuu(&self, midnight: Timestamp) -> [u8; 8] {
        #[inline(always)]
        fn write_digits_fast<const OFFSET: usize>(buf: &mut [u8; 8], val: u8) {
            let (tens, ones) = (val / 10, val % 10);
            buf[OFFSET] = tens + b'0';
            buf[OFFSET + 1] = ones + b'0';
        }

        let mut out = [0u8; 8];

        let day_nanos = self.0 - midnight.0;

        let hour = day_nanos / NANOS_PER_HOUR;
        let min = (day_nanos % NANOS_PER_HOUR) / NANOS_PER_MIN;
        let sec = (day_nanos % NANOS_PER_MIN) / NANOS_PER_SEC;
        let cent = (day_nanos % NANOS_PER_SEC) / NANOS_PER_CENT;

        write_digits_fast::<0>(&mut out, hour as u8);
        write_digits_fast::<2>(&mut out, min as u8);
        write_digits_fast::<4>(&mut out, sec as u8);
        write_digits_fast::<6>(&mut out, cent as u8);

        out
    }
}

#[test]
fn test_parse_hhmmssuu() {
    let [hour, min, sec, cent] = Timestamp::parse_hhmmssuu(b"12304580");
    assert_eq!(hour, 12);
    assert_eq!(min, 30);
    assert_eq!(sec, 45);
    assert_eq!(cent, 80);

    let [hour, min, sec, cent] = Timestamp::parse_hhmmssuu(b"99999999");
    assert_eq!(hour, 99);
    assert_eq!(min, 99);
    assert_eq!(sec, 99);
    assert_eq!(cent, 99);
}
