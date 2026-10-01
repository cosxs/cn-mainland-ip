//! Parses the NRO combined delegation statistics into a [`Registry`].

use std::collections::HashSet;
use std::io::BufRead;
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use jiff::Timestamp;
use jiff::civil::Date;
use jiff::tz::TimeZone;

use crate::model::{Asn, Country, Family, PerFamily};
use crate::ranges::{self, Range};

/// Allocated address space, CN-registered ASNs and the country behind every block.
#[derive(Debug)]
pub struct Registry {
    /// Start (UTC) of the day the file describes.
    pub published: Timestamp,
    pub records: usize,
    cn_asns: HashSet<Asn>,
    blocks: PerFamily<Vec<Block>>,
    allocated: PerFamily<Vec<Range>>,
    cn: PerFamily<Vec<Range>>,
}

#[derive(Debug)]
struct Block {
    range: Range,
    country: Country,
}

impl Registry {
    /// Reads `nro-delegated-stats`. Only `allocated` and `assigned` records count as registered;
    /// the header's record total guards against truncated downloads.
    pub fn parse(reader: impl BufRead) -> Result<Self> {
        let mut lines = reader.lines();
        let header = lines.next().context("empty NRO file")??;
        let [_, "nro", date, total, ..] = header.split('|').collect::<Vec<_>>()[..] else {
            bail!("unexpected NRO header: {header}");
        };
        let published = Date::strptime("%Y%m%d", date)?.to_zoned(TimeZone::UTC)?.timestamp();
        let total: usize = total.parse().context("NRO record total")?;

        let mut records = 0;
        let mut cn_asns = HashSet::new();
        let mut blocks = PerFamily::<Vec<Block>>::default();
        for line in lines {
            let line = line?;
            let [_, cc, kind, start, value, _, status, ..] = line.split('|').collect::<Vec<_>>()[..] else {
                continue; // comments and summary lines
            };
            records += 1;
            let Some(country) = Country::parse(cc) else {
                continue;
            };
            if !matches!(status, "allocated" | "assigned") {
                continue;
            }
            match kind {
                "asn" if country == Country::CN => {
                    let (first, count): (u32, u32) = (start.parse()?, value.parse()?);
                    cn_asns.extend((first..first.saturating_add(count)).map(Asn));
                }
                "ipv4" => {
                    let first = u128::from(start.parse::<Ipv4Addr>()?.to_bits());
                    let count: u128 = value.parse()?;
                    let last = first + count.checked_sub(1).context("empty IPv4 block")?;
                    blocks.v4.push(Block { range: first..=last, country });
                }
                "ipv6" => {
                    let net = IpNet::new(start.parse::<Ipv6Addr>()?.into(), value.parse()?)?;
                    blocks.v6.push(Block { range: ranges::span(&net), country });
                }
                _ => {}
            }
        }
        ensure!(records == total, "NRO file truncated: {records} of {total} records");

        let mut registry = Self {
            published,
            records,
            cn_asns,
            blocks,
            allocated: PerFamily::default(),
            cn: PerFamily::default(),
        };
        for family in Family::ALL {
            let blocks = &mut registry.blocks[family];
            blocks.sort_unstable_by_key(|b| *b.range.start());
            registry.allocated[family] = ranges::merge(blocks.iter().map(|b| b.range.clone()));
            registry.cn[family] =
                ranges::merge(blocks.iter().filter(|b| b.country == Country::CN).map(|b| b.range.clone()));
        }
        Ok(registry)
    }

    pub fn is_cn_asn(&self, asn: Asn) -> bool {
        self.cn_asns.contains(&asn)
    }

    /// Registration country of the block holding the prefix's first address.
    pub fn country_of(&self, net: &IpNet) -> Option<Country> {
        let blocks = &self.blocks[Family::of(net)];
        let addr = ranges::to_u128(net.network());
        let i = blocks.partition_point(|b| *b.range.start() <= addr).checked_sub(1)?;
        let block = &blocks[i];
        block.range.contains(&addr).then_some(block.country)
    }

    pub fn allocated(&self, family: Family) -> &[Range] {
        &self.allocated[family]
    }

    pub fn cn(&self, family: Family) -> &[Range] {
        &self.cn[family]
    }
}

#[cfg(test)]
#[allow(clippy::single_range_in_vec_init)] // one-element range lists are intended
pub(crate) mod tests {
    use super::*;

    pub const SAMPLE: &str = "\
2|nro|20260929|8|19821213|20260929|+0000
nro|*|asn|*|4|summary
nro|*|ipv4|*|3|summary
nro|*|ipv6|*|1|summary
apnic|CN|asn|4134|1|20020801|allocated|A1|e-stats
apnic|CN|asn|4808|1|20020801|allocated|A1|e-stats
apnic|CN|asn|37963|1|20060725|allocated|A4|e-stats
arin|US|asn|7018|1|19960628|assigned|B1|e-stats
apnic|AU|ipv4|1.0.0.0|256|20110811|assigned|C1|e-stats
apnic|CN|ipv4|1.0.1.0|768|20110414|allocated|A2|e-stats
iana|ZZ|ipv4|10.0.0.0|16777216|19950501|reserved|ietf|iana
apnic|CN|ipv6|240e::|20|20150112|allocated|A3|e-stats
";

    pub fn sample() -> Registry {
        Registry::parse(SAMPLE.as_bytes()).unwrap()
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn parses_registrations() {
        let registry = sample();
        assert_eq!(registry.records, 8);
        assert!(registry.is_cn_asn(Asn(4134)) && registry.is_cn_asn(Asn(37963)));
        assert!(!registry.is_cn_asn(Asn(7018)));
        assert_eq!(registry.country_of(&net("1.0.2.0/24")), Some(Country::CN));
        assert_eq!(registry.country_of(&net("1.0.0.0/24")), Country::parse("AU"));
        assert_eq!(registry.country_of(&net("10.0.0.0/8")), None);
        assert_eq!(registry.country_of(&net("240e:1::/32")), Some(Country::CN));
        assert_eq!(registry.allocated(Family::V4).len(), 1, "AU and CN blocks are adjacent");
        let (first, last) = (ranges::span(&net("1.0.1.0/24")), ranges::span(&net("1.0.3.0/24")));
        assert_eq!(registry.cn(Family::V4), [*first.start()..=*last.end()]);
    }

    #[test]
    fn rejects_truncated_file() {
        let truncated = SAMPLE.lines().take(8).collect::<Vec<_>>().join("\n");
        let err = Registry::parse(truncated.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("truncated"), "{err}");
    }
}
