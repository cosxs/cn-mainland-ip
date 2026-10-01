//! Renders the published files: a plain CIDR list, plus one module per client for its rule-set
//! formats. They depend only on the classification and the sources' dates, so identical inputs
//! give byte-identical files.

mod egern;
mod mihomo;
mod quantumult_x;
mod shadowrocket;
mod sing_box;
mod surge;

use std::fmt::{Display, Write as _};
use std::net::IpAddr;

use anyhow::Result;
use ipnet::IpNet;
use jiff::Timestamp;

use crate::model::{Family, PerFamily};
use crate::ranges::{self, Range};

// Layout of `release/`. A new client gets its own directory; existing paths never move.

/// Plain CIDR list, IPv4 first.
pub const TEXT: &str = "text/cn.txt";
pub const SURGE: &str = "surge/cn.list";
/// Loon reads Surge's format for its remote rules.
pub const LOON: &str = "loon/cn.list";
pub const SHADOWROCKET: &str = "shadowrocket/cn.list";
pub const QUANTUMULT_X: &str = "quantumult-x/cn.list";
pub const MIHOMO_YAML: &str = "mihomo/cn.yaml";
pub const MIHOMO_MRS: &str = "mihomo/cn.mrs";
pub const SING_BOX_JSON: &str = "sing-box/cn.json";
pub const SING_BOX_SRS: &str = "sing-box/cn.srs";
pub const EGERN: &str = "egern/cn.yaml";

/// Where the data came from, for the file header.
#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub snapshot: Timestamp,
    pub collectors: usize,
    pub nro: Timestamp,
    pub rpki: Option<Timestamp>,
}

#[derive(Debug)]
pub struct Artifacts {
    /// Relative path and content of every published file.
    pub files: Vec<(&'static str, Vec<u8>)>,
    pub entries: PerFamily<usize>,
}

impl Artifacts {
    pub fn file(&self, path: &str) -> Option<&[u8]> {
        self.files.iter().find(|(p, _)| *p == path).map(|(_, content)| content.as_slice())
    }
}

pub fn render(included: &PerFamily<Vec<Range>>, header: &Header) -> Result<Artifacts> {
    let nets: PerFamily<Vec<IpNet>> = PerFamily::from_fn(|family| {
        included[family].iter().flat_map(|range| ranges::cidrs(range, family)).collect()
    });
    let banner = header.banner(&nets);
    let surge = surge::render(&banner, &nets);
    Ok(Artifacts {
        files: vec![
            (TEXT, lines(nets.v4.iter().chain(&nets.v6), "", "").into()),
            (SURGE, surge.clone().into()),
            (LOON, surge.into()),
            (SHADOWROCKET, shadowrocket::render(&banner, &nets).into()),
            (QUANTUMULT_X, quantumult_x::render(&banner, &nets).into()),
            (MIHOMO_YAML, mihomo::yaml(&banner, &nets).into()),
            (MIHOMO_MRS, mihomo::mrs(included, &nets)),
            (SING_BOX_JSON, sing_box::source(&nets)?.into()),
            (SING_BOX_SRS, sing_box::binary(included)?),
            (EGERN, egern::render(&banner, &nets).into()),
        ],
        entries: PerFamily::from_fn(|family| nets[family].len()),
    })
}

impl Header {
    /// Comment lines that open every rule set.
    fn banner(&self, nets: &PerFamily<Vec<IpNet>>) -> String {
        let day = |t: Timestamp| t.strftime("%Y-%m-%d").to_string();
        format!(
            "# cn-mainland-ip: mainland China IP ranges derived from BGP routing data\n\
             # snapshot {} from {} collectors; NRO {}; RPKI {}\n\
             # {} IPv4 and {} IPv6 entries; license MIT\n",
            self.snapshot,
            self.collectors,
            day(self.nro),
            self.rpki.map_or_else(|| "-".to_owned(), day),
            nets.v4.len(),
            nets.v6.len(),
        )
    }
}

/// One item per line, wrapped in `prefix` and `suffix`.
fn lines<T: Display>(items: impl IntoIterator<Item = T>, prefix: &str, suffix: &str) -> String {
    items.into_iter().fold(String::new(), |mut out, item| {
        let _ = writeln!(out, "{prefix}{item}{suffix}"); // writing to a String cannot fail
        out
    })
}

/// A YAML block sequence. Items are quoted because IPv6 prefixes contain colons.
fn yaml_list<T: Display>(items: impl IntoIterator<Item = T>) -> String {
    lines(items, "  - '", "'")
}

/// First and last address of every included range, IPv4 first. Sorted and coalesced, this is the
/// form netipx's `IPSet` keeps, which both binary formats store as is.
fn bounds(included: &PerFamily<Vec<Range>>) -> impl Iterator<Item = [IpAddr; 2]> + '_ {
    Family::ALL.into_iter().flat_map(move |family| {
        included[family].iter().map(move |range| [*range.start(), *range.end()].map(|v| family.addr(v)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `1.0.0.0/23` and `240e::/20`.
    pub(super) fn sample() -> PerFamily<Vec<Range>> {
        PerFamily {
            v4: vec![ranges::span(&"1.0.0.0/23".parse().unwrap())],
            v6: vec![ranges::span(&"240e::/20".parse().unwrap())],
        }
    }
}
