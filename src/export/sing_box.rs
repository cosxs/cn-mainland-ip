//! sing-box rule-sets: the JSON source format, and the binary `.srs` that
//! `sing-box rule-set compile` makes from it. Both are version 1, which every sing-box since 1.8.0
//! reads; the IP CIDR encoding has not changed since.

use std::io::{self, Write as _};
use std::iter;
use std::net::IpAddr;

use flate2::Compression;
use flate2::write::ZlibEncoder;
use ipnet::IpNet;
use serde::Serialize;

use super::bounds;
use crate::model::PerFamily;
use crate::ranges::Range;

const VERSION: u8 = 1;

#[derive(Serialize)]
struct RuleSet<'a> {
    version: u8,
    rules: [Rule<'a>; 1],
}

#[derive(Serialize)]
struct Rule<'a> {
    ip_cidr: Vec<&'a IpNet>,
}

/// JSON has no comments, so there is no banner.
pub(super) fn source(nets: &PerFamily<Vec<IpNet>>) -> serde_json::Result<String> {
    let rule_set =
        RuleSet { version: VERSION, rules: [Rule { ip_cidr: nets.v4.iter().chain(&nets.v6).collect() }] };
    // One prefix per line keeps the daily diffs readable.
    Ok(serde_json::to_string_pretty(&rule_set)? + "\n")
}

/// Tags from sing-box's `common/srs` encoding.
const MAGIC: &[u8; 3] = b"SRS";
const DEFAULT_RULE: u8 = 0;
const ITEM_IP_CIDR: u8 = 6;
const ITEM_FINAL: u8 = 0xFF;
const IP_SET_VERSION: u8 = 1;

/// The same rule as [`source`]: a header, then a zlib stream holding one rule with one IP set.
pub(super) fn binary(included: &PerFamily<Vec<Range>>) -> io::Result<Vec<u8>> {
    let ranges: Vec<_> = bounds(included).collect();
    // The rule count is a uvarint: 1 is the single byte 0x01.
    let mut body = vec![1, DEFAULT_RULE, ITEM_IP_CIDR, IP_SET_VERSION];
    body.extend((ranges.len() as u64).to_be_bytes());
    for addr in ranges.iter().flatten() {
        // Each address is prefixed with its length, again a one-byte uvarint.
        match addr {
            IpAddr::V4(a) => body.extend(iter::once(4).chain(a.octets())),
            IpAddr::V6(a) => body.extend(iter::once(16).chain(a.octets())),
        }
    }
    body.extend([ITEM_FINAL, 0]); // no more items; not inverted

    let mut encoder = ZlibEncoder::new([MAGIC.as_slice(), &[VERSION]].concat(), Compression::best());
    encoder.write_all(&body)?;
    encoder.finish()
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;
    use std::net::Ipv6Addr;

    use flate2::read::ZlibDecoder;

    use super::*;
    use crate::export::tests::sample;

    #[test]
    fn binary_follows_the_srs_layout() {
        let file = binary(&sample()).unwrap();
        assert_eq!(&file[..4], b"SRS\x01");
        let mut body = Vec::new();
        ZlibDecoder::new(&file[4..]).read_to_end(&mut body).unwrap();

        let v6 = |s: &str| s.parse::<Ipv6Addr>().unwrap().octets();
        let mut expected = vec![1, 0, 6, 1]; // one default rule; ip_cidr; IP set version
        expected.extend(2_u64.to_be_bytes());
        expected.extend([4, 1, 0, 0, 0, 4, 1, 0, 1, 255]);
        expected.extend(iter::once(16).chain(v6("240e::")));
        expected.extend(iter::once(16).chain(v6("240e:fff:ffff:ffff:ffff:ffff:ffff:ffff")));
        expected.extend([0xFF, 0]);
        assert_eq!(body, expected);
    }
}
