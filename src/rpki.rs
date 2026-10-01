//! Route origin validation against ROAs from the RIPE NCC daily RPKI archive.

use std::collections::HashMap;
use std::io::Read;

use anyhow::{Context, Result};
use ipnet::IpNet;
use jiff::Timestamp;
use serde::Deserialize;

use crate::model::Asn;

/// One trust anchor's `output.json`.
#[derive(Debug, Deserialize)]
pub struct Dump {
    metadata: Metadata,
    roas: Vec<RawRoa>,
}

#[derive(Debug, Deserialize)]
struct Metadata {
    generated: i64,
}

#[derive(Debug, Deserialize)]
struct RawRoa {
    asn: String,
    prefix: IpNet,
    #[serde(rename = "maxLength")]
    max_length: u8,
}

impl Dump {
    pub fn parse(reader: impl Read) -> Result<Self> {
        Ok(serde_json::from_reader(reader)?)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Validity {
    Valid,
    Invalid,
    NotFound,
}

/// All ROAs, indexed by prefix.
#[derive(Debug, Default)]
pub struct Roas {
    by_prefix: HashMap<IpNet, Vec<(Asn, u8)>>,
    /// Generation time of the oldest dump.
    pub generated: Option<Timestamp>,
}

impl Roas {
    pub fn from_dumps(dumps: impl IntoIterator<Item = Dump>) -> Result<Self> {
        let mut roas = Self::default();
        for dump in dumps {
            let generated = Timestamp::from_second(dump.metadata.generated)?;
            roas.generated = Some(roas.generated.map_or(generated, |g| g.min(generated)));
            for roa in dump.roas {
                let asn = roa.asn.strip_prefix("AS").unwrap_or(&roa.asn);
                let asn = Asn(asn.parse().with_context(|| format!("ROA origin {}", roa.asn))?);
                roas.by_prefix.entry(roa.prefix.trunc()).or_default().push((asn, roa.max_length));
            }
        }
        Ok(roas)
    }

    /// RFC 6811: a route is valid if a covering ROA matches its origin and length,
    /// invalid if covering ROAs exist but none matches, and not found otherwise.
    pub fn validate(&self, prefix: IpNet, origin: Asn) -> Validity {
        let mut covered = false;
        for net in std::iter::successors(Some(prefix.trunc()), IpNet::supernet) {
            for &(asn, max_length) in self.by_prefix.get(&net).into_iter().flatten() {
                if asn == origin && prefix.prefix_len() <= max_length {
                    return Validity::Valid;
                }
                covered = true;
            }
        }
        if covered { Validity::Invalid } else { Validity::NotFound }
    }

    pub fn len(&self) -> usize {
        self.by_prefix.values().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.by_prefix.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roas() -> Roas {
        let json = r#"{
            "metadata": { "generated": 1790656989, "generatedTime": "2026-09-29T04:43:09Z" },
            "roas": [
                { "asn": "AS4134", "prefix": "1.0.0.0/16", "maxLength": 24, "ta": "apnic" },
                { "asn": "AS0", "prefix": "2.0.0.0/8", "maxLength": 8, "ta": "ripencc" }
            ]
        }"#;
        Roas::from_dumps([Dump::parse(json.as_bytes()).unwrap()]).unwrap()
    }

    #[test]
    fn validates_origins() {
        let roas = roas();
        let check = |p: &str, asn| roas.validate(p.parse().unwrap(), Asn(asn));
        assert_eq!(check("1.0.1.0/24", 4134), Validity::Valid);
        assert_eq!(check("1.0.1.0/24", 64_500), Validity::Invalid, "wrong origin");
        assert_eq!(check("1.0.1.128/25", 4134), Validity::Invalid, "longer than maxLength");
        assert_eq!(check("2.1.0.0/16", 4134), Validity::Invalid, "AS0 covers it");
        assert_eq!(check("3.0.0.0/8", 4134), Validity::NotFound);
        assert_eq!(roas.generated, Some(Timestamp::from_second(1_790_656_989).unwrap()));
    }
}
