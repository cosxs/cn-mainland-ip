//! Domain types shared by every stage of the pipeline.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::{Index, IndexMut};

use ipnet::IpNet;
use serde::{Serialize, Serializer};

/// An autonomous system number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct Asn(pub u32);

impl Asn {
    /// Whether the ASN may originate routes on the public Internet, i.e. it is not
    /// reserved, private or for documentation (RFC 5398, 6793, 6996, 7300).
    pub const fn is_public(self) -> bool {
        !matches!(self.0, 0 | 23_456 | 64_496..=131_071 | 4_200_000_000..)
    }
}

impl fmt::Display for Asn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AS{}", self.0)
    }
}

/// An ISO 3166 two-letter code as used in RIR delegation files.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Country([u8; 2]);

impl Country {
    pub const CN: Self = Self(*b"CN");

    pub fn parse(code: &str) -> Option<Self> {
        <[u8; 2]>::try_from(code.as_bytes()).ok().map(Self)
    }
}

impl fmt::Display for Country {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|&b| write!(f, "{}", char::from(b)))
    }
}

impl Serialize for Country {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// IP address family. Addresses of both families are handled as `u128`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub const ALL: [Self; 2] = [Self::V4, Self::V6];

    pub const fn of(net: &IpNet) -> Self {
        match net {
            IpNet::V4(_) => Self::V4,
            IpNet::V6(_) => Self::V6,
        }
    }

    pub const fn bits(self) -> u8 {
        match self {
            Self::V4 => 32,
            Self::V6 => 128,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::V4 => "ipv4",
            Self::V6 => "ipv6",
        }
    }

    /// Converts a `u128` address back; IPv4 addresses always fit in the low 32 bits.
    #[allow(clippy::cast_possible_truncation)]
    pub fn addr(self, value: u128) -> IpAddr {
        match self {
            Self::V4 => IpAddr::V4(Ipv4Addr::from(value as u32)),
            Self::V6 => IpAddr::V6(Ipv6Addr::from(value)),
        }
    }
}

/// A value per address family.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PerFamily<T> {
    pub v4: T,
    pub v6: T,
}

impl<T> PerFamily<T> {
    pub fn from_fn(mut f: impl FnMut(Family) -> T) -> Self {
        Self { v4: f(Family::V4), v6: f(Family::V6) }
    }
}

impl<T> Index<Family> for PerFamily<T> {
    type Output = T;

    fn index(&self, family: Family) -> &T {
        match family {
            Family::V4 => &self.v4,
            Family::V6 => &self.v6,
        }
    }
}

impl<T> IndexMut<Family> for PerFamily<T> {
    fn index_mut(&mut self, family: Family) -> &mut T {
        match family {
            Family::V4 => &mut self.v4,
            Family::V6 => &mut self.v6,
        }
    }
}

/// Routing evidence for an address range after longest-prefix matching.
/// The order matters: several origins of one prefix combine to the strongest status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BgpStatus {
    Unannounced,
    /// Announced, but no origin is registered in CN.
    Foreign,
    /// A CN-registered origin, but no path proves the route enters through a mainland backbone.
    DomesticWeak,
    /// At least one path reaches the origin through a mainland backbone.
    Domestic,
}

impl BgpStatus {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unannounced => "unannounced",
            Self::Foreign => "foreign",
            Self::DomesticWeak => "domestic_weak",
            Self::Domestic => "domestic",
        }
    }
}

/// Why a range was included or excluded; the codes appear verbatim in reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    Unallocated,
    BgpDomestic,
    RegistryFallback,
    NoDomesticPath,
    ForeignOrigin,
    NoEvidence,
}

impl Reason {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unallocated => "unallocated",
            Self::BgpDomestic => "bgp_domestic",
            Self::RegistryFallback => "registry_fallback",
            Self::NoDomesticPath => "no_domestic_path",
            Self::ForeignOrigin => "foreign_origin",
            Self::NoEvidence => "no_evidence",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Include(Reason),
    Exclude(Reason),
}

impl Verdict {
    pub const fn is_included(self) -> bool {
        matches!(self, Self::Include(_))
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Include(_) => "include",
            Self::Exclude(_) => "exclude",
        }
    }

    pub const fn reason(self) -> Reason {
        match self {
            Self::Include(reason) | Self::Exclude(reason) => reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_asns() {
        assert!(Asn(4134).is_public());
        assert!(Asn(4_199_999_999).is_public());
        for reserved in [0, 23_456, 64_496, 65_000, 65_535, 131_071, 4_200_000_000, u32::MAX] {
            assert!(!Asn(reserved).is_public(), "{reserved}");
        }
    }

    #[test]
    fn codes_match_serde() {
        use {BgpStatus as B, Reason as R};
        for status in [B::Unannounced, B::Foreign, B::DomesticWeak, B::Domestic] {
            assert_eq!(serde_json::to_value(status).unwrap(), status.code());
        }
        let reasons = [
            R::Unallocated,
            R::BgpDomestic,
            R::RegistryFallback,
            R::NoDomesticPath,
            R::ForeignOrigin,
            R::NoEvidence,
        ];
        for reason in reasons {
            assert_eq!(serde_json::to_value(reason).unwrap(), reason.code());
        }
    }
}
