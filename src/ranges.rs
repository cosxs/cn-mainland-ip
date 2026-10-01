//! Inclusive address ranges over `u128`, shared by IPv4 and IPv6.

use std::net::IpAddr;
use std::ops::RangeInclusive;

use ipnet::IpNet;

use crate::model::Family;

pub type Range = RangeInclusive<u128>;

/// The addresses covered by a prefix.
pub fn span(net: &IpNet) -> Range {
    let (lo, hi) = (net.network(), net.broadcast());
    to_u128(lo)..=to_u128(hi)
}

pub fn to_u128(addr: IpAddr) -> u128 {
    match addr {
        IpAddr::V4(a) => u128::from(a.to_bits()),
        IpAddr::V6(a) => a.to_bits(),
    }
}

/// Membership test over sorted, disjoint ranges for addresses visited in increasing order.
pub struct Cursor<'a> {
    ranges: &'a [Range],
}

impl<'a> Cursor<'a> {
    pub fn new(ranges: &'a [Range]) -> Self {
        Self { ranges }
    }

    pub fn contains(&mut self, addr: u128) -> bool {
        while let [first, rest @ ..] = self.ranges
            && *first.end() < addr
        {
            self.ranges = rest;
        }
        self.ranges.first().is_some_and(|r| *r.start() <= addr)
    }
}

/// Sorts ranges and coalesces overlapping or adjacent ones.
pub fn merge(ranges: impl IntoIterator<Item = Range>) -> Vec<Range> {
    let mut ranges: Vec<Range> = ranges.into_iter().collect();
    ranges.sort_unstable_by_key(|r| *r.start());
    let mut merged: Vec<Range> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match merged.last_mut() {
            Some(last) if *range.start() <= last.end().saturating_add(1) => {
                *last = *last.start()..=*last.end().max(range.end());
            }
            _ => merged.push(range),
        }
    }
    merged
}

/// Splits a range into the fewest CIDR blocks.
pub fn cidrs(range: &Range, family: Family) -> Vec<IpNet> {
    let bits = u32::from(family.bits());
    let (mut start, end) = (*range.start(), *range.end());
    let mut out = Vec::new();
    loop {
        // Host bits of the largest block that is aligned at `start` and does not pass `end`.
        let aligned = start.trailing_zeros().min(bits);
        let fits = (end - start).checked_add(1).map_or(128, u128::ilog2);
        let host = aligned.min(fits);
        #[allow(clippy::cast_possible_truncation)] // at most 128
        out.push(IpNet::new_assert(family.addr(start), (bits - host) as u8));
        let last = start + u128::MAX.checked_shr(128 - host).unwrap_or(0);
        if last >= end {
            return out;
        }
        start = last + 1;
    }
}

/// Number of addresses, counted in units of `/unit` blocks.
pub fn size(ranges: &[Range], family: Family, unit: u8) -> u128 {
    let shift = u32::from(family.bits() - unit);
    ranges.iter().map(|r| ((r.end() - r.start()) >> shift) + 1).sum()
}

#[cfg(test)]
#[allow(clippy::single_range_in_vec_init)] // one-element range lists are intended
mod tests {
    use super::*;

    fn nets(range: Range, family: Family) -> Vec<String> {
        cidrs(&range, family).iter().map(ToString::to_string).collect()
    }

    fn v4(s: &str) -> u128 {
        to_u128(s.parse().unwrap())
    }

    #[test]
    fn splits_into_fewest_cidrs() {
        assert_eq!(nets(v4("10.0.0.0")..=v4("10.0.0.255"), Family::V4), ["10.0.0.0/24"]);
        assert_eq!(
            nets(v4("10.0.0.1")..=v4("10.0.0.6"), Family::V4),
            ["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"]
        );
        assert_eq!(nets(0..=u128::from(u32::MAX), Family::V4), ["0.0.0.0/0"]);
        assert_eq!(nets(0..=u128::MAX, Family::V6), ["::/0"]);
        assert_eq!(nets(u128::MAX..=u128::MAX, Family::V6), ["ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"]);
    }

    #[test]
    fn merges_overlapping_and_adjacent() {
        assert_eq!(merge([5..=9, 0..=3, 4..=4, 20..=30, 25..=26]), [0..=9, 20..=30]);
        assert_eq!(merge([0..=u128::MAX, 7..=8]), [0..=u128::MAX]);
    }

    #[test]
    fn cursor_walks_forward() {
        let ranges = [10..=19, 30..=39];
        let mut cursor = Cursor::new(&ranges);
        let hits: Vec<bool> = [0, 10, 19, 20, 35, 40].into_iter().map(|a| cursor.contains(a)).collect();
        assert_eq!(hits, [false, true, true, false, true, false]);
    }

    #[test]
    fn sizes_in_units() {
        let r = [v4("10.0.0.0")..=v4("10.0.1.255")];
        assert_eq!(size(&r, Family::V4, 32), 512);
        assert_eq!(size(&r, Family::V4, 24), 2);
    }
}
