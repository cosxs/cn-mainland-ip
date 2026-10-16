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

/// Paths of one complete set of files, one per format.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    pub text: &'static str,
    pub surge: &'static str,
    pub loon: &'static str,
    pub shadowrocket: &'static str,
    pub quantumult_x: &'static str,
    pub mihomo_yaml: &'static str,
    pub mihomo_mrs: &'static str,
    pub sing_box_json: &'static str,
    pub sing_box_srs: &'static str,
    pub egern: &'static str,
}

/// Both families.
pub const ALL: Layout = Layout {
    text: TEXT,
    surge: SURGE,
    loon: LOON,
    shadowrocket: SHADOWROCKET,
    quantumult_x: QUANTUMULT_X,
    mihomo_yaml: MIHOMO_YAML,
    mihomo_mrs: MIHOMO_MRS,
    sing_box_json: SING_BOX_JSON,
    sing_box_srs: SING_BOX_SRS,
    egern: EGERN,
};

/// IPv4 only, next to each file of [`ALL`] with `-ipv4` added to its name.
pub const V4: Layout = Layout {
    text: "text/cn-ipv4.txt",
    surge: "surge/cn-ipv4.list",
    loon: "loon/cn-ipv4.list",
    shadowrocket: "shadowrocket/cn-ipv4.list",
    quantumult_x: "quantumult-x/cn-ipv4.list",
    mihomo_yaml: "mihomo/cn-ipv4.yaml",
    mihomo_mrs: "mihomo/cn-ipv4.mrs",
    sing_box_json: "sing-box/cn-ipv4.json",
    sing_box_srs: "sing-box/cn-ipv4.srs",
    egern: "egern/cn-ipv4.yaml",
};

/// IPv6 only, named like [`V4`].
pub const V6: Layout = Layout {
    text: "text/cn-ipv6.txt",
    surge: "surge/cn-ipv6.list",
    loon: "loon/cn-ipv6.list",
    shadowrocket: "shadowrocket/cn-ipv6.list",
    quantumult_x: "quantumult-x/cn-ipv6.list",
    mihomo_yaml: "mihomo/cn-ipv6.yaml",
    mihomo_mrs: "mihomo/cn-ipv6.mrs",
    sing_box_json: "sing-box/cn-ipv6.json",
    sing_box_srs: "sing-box/cn-ipv6.srs",
    egern: "egern/cn-ipv6.yaml",
};

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
    let only =
        |family: Family| PerFamily::from_fn(|f| if f == family { included[f].clone() } else { Vec::new() });
    let mut files = render_set(included, header, &ALL)?;
    files.extend(render_set(&only(Family::V4), header, &V4)?);
    files.extend(render_set(&only(Family::V6), header, &V6)?);
    Ok(Artifacts {
        files,
        entries: PerFamily::from_fn(|family| {
            included[family].iter().map(|range| ranges::cidrs(range, family).len()).sum()
        }),
    })
}

/// Every format for the ranges in `included`, at the paths in `layout`.
fn render_set(
    included: &PerFamily<Vec<Range>>,
    header: &Header,
    layout: &Layout,
) -> Result<Vec<(&'static str, Vec<u8>)>> {
    let nets: PerFamily<Vec<IpNet>> = PerFamily::from_fn(|family| {
        included[family].iter().flat_map(|range| ranges::cidrs(range, family)).collect()
    });
    let banner = header.banner(&nets);
    let surge = surge::render(&banner, &nets);
    Ok(vec![
        (layout.text, lines(nets.v4.iter().chain(&nets.v6), "", "").into()),
        (layout.surge, surge.clone().into()),
        (layout.loon, surge.into()),
        (layout.shadowrocket, shadowrocket::render(&banner, &nets).into()),
        (layout.quantumult_x, quantumult_x::render(&banner, &nets).into()),
        (layout.mihomo_yaml, mihomo::yaml(&banner, &nets).into()),
        (layout.mihomo_mrs, mihomo::mrs(included, &nets)),
        (layout.sing_box_json, sing_box::source(&nets)?.into()),
        (layout.sing_box_srs, sing_box::binary(included)?),
        (layout.egern, egern::render(&banner, &nets).into()),
    ])
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
