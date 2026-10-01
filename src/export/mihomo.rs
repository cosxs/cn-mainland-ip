//! mihomo rule providers with `behavior: ipcidr`: YAML, and the binary MRS that
//! `mihomo convert-ruleset ipcidr yaml` makes from it (mihomo 1.18.7 and later).

use std::net::IpAddr;

use ipnet::IpNet;
use ruzstd::encoding::{CompressionLevel, compress_to_vec};

use super::{bounds, yaml_list};
use crate::model::PerFamily;
use crate::ranges::Range;

pub(super) fn yaml(banner: &str, nets: &PerFamily<Vec<IpNet>>) -> String {
    format!("{banner}payload:\n{}", yaml_list(nets.v4.iter().chain(&nets.v6)))
}

/// Fields of mihomo's MRS v1 encoding.
const MAGIC: &[u8; 4] = b"MRS\x01";
const BEHAVIOR_IPCIDR: u8 = 1;
const IP_SET_VERSION: u8 = 1;

/// A zstd stream of a header and the IP set. mihomo's integers are big-endian `int64`, which for
/// these counts are the same bytes as `u64`.
pub(super) fn mrs(included: &PerFamily<Vec<Range>>, nets: &PerFamily<Vec<IpNet>>) -> Vec<u8> {
    let ranges: Vec<_> = bounds(included).collect();
    let mut body = MAGIC.to_vec();
    body.push(BEHAVIOR_IPCIDR);
    // The rule count mihomo shows, the same as for the YAML file.
    body.extend(((nets.v4.len() + nets.v6.len()) as u64).to_be_bytes());
    body.extend(0_u64.to_be_bytes()); // length of the reserved extra field
    body.push(IP_SET_VERSION);
    body.extend((ranges.len() as u64).to_be_bytes());
    for addr in ranges.iter().flatten() {
        // Every address takes 16 bytes, IPv4 mapped into IPv6.
        let v6 = match *addr {
            IpAddr::V4(a) => a.to_ipv6_mapped(),
            IpAddr::V6(a) => a,
        };
        body.extend(v6.octets());
    }
    // The highest level ruzstd implements.
    compress_to_vec(body.as_slice(), CompressionLevel::Fastest)
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;
    use std::net::Ipv6Addr;

    use ruzstd::decoding::StreamingDecoder;

    use super::*;
    use crate::export::tests::sample;

    #[test]
    fn mrs_follows_the_mihomo_layout() {
        let nets =
            PerFamily { v4: vec!["1.0.0.0/23".parse().unwrap()], v6: vec!["240e::/20".parse().unwrap()] };
        let file = mrs(&sample(), &nets);
        let mut body = Vec::new();
        StreamingDecoder::new(file.as_slice()).unwrap().read_to_end(&mut body).unwrap();

        let mut expected = b"MRS\x01\x01".to_vec(); // magic; ipcidr
        expected.extend(2_u64.to_be_bytes()); // rules
        expected.extend(0_u64.to_be_bytes()); // no extra
        expected.push(1); // IP set version
        expected.extend(2_u64.to_be_bytes()); // ranges
        let addrs =
            ["::ffff:1.0.0.0", "::ffff:1.0.1.255", "240e::", "240e:fff:ffff:ffff:ffff:ffff:ffff:ffff"];
        expected.extend(addrs.iter().flat_map(|a| a.parse::<Ipv6Addr>().unwrap().octets()));
        assert_eq!(body, expected);
    }
}
