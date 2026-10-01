//! Decides whether an AS path proves that a prefix is reached through a mainland backbone.

use ipnet::IpNet;

use crate::model::{Asn, Country};
use crate::nro::Registry;
use crate::params::BACKBONE_ASNS;

/// Returns the backbone that makes `path` (collector first, origin last, prepends removed)
/// a domestic path for `prefix`.
///
/// The walk starts at the origin and continues while ASNs are CN-registered; it may not cross
/// a foreign network. It stops at the first backbone. A backbone that is the origin or its direct
/// upstream does not count for prefixes registered outside CN: that is what the overseas points
/// of presence of China Telecom's CN2 and 163 networks look like.
pub fn domestic_via(path: &[Asn], prefix: &IpNet, registry: &Registry) -> Option<Asn> {
    let (hop, &backbone) = path
        .iter()
        .rev()
        .take_while(|&&asn| registry.is_cn_asn(asn))
        .enumerate()
        .find(|(_, asn)| BACKBONE_ASNS.contains(asn))?;
    (hop > 1 || registry.country_of(prefix) == Some(Country::CN)).then_some(backbone)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nro::tests::sample;

    fn via(path: &[u32], prefix: &str) -> Option<Asn> {
        let path: Vec<Asn> = path.iter().copied().map(Asn).collect();
        domestic_via(&path, &prefix.parse().unwrap(), &sample())
    }

    // The sample registry knows AS4134 (backbone), AS4808 and AS37963 (CN) and AS7018 (US);
    // 1.0.1.0/24 is registered in CN, 1.0.0.0/24 in AU.
    #[test]
    fn backbone_upstream_of_a_cn_network() {
        assert_eq!(via(&[7018, 4134, 4808, 37963], "1.0.0.0/24"), Some(Asn(4134)));
        assert_eq!(via(&[7018, 4134, 4808], "1.0.1.0/24"), Some(Asn(4134)));
    }

    #[test]
    fn stops_at_the_first_foreign_network() {
        assert_eq!(via(&[4134, 7018, 4808], "1.0.1.0/24"), None);
        assert_eq!(via(&[4134, 7018], "1.0.1.0/24"), None);
    }

    #[test]
    fn overseas_pop_exception() {
        // Backbone next to (or equal to) the origin: counts only for CN-registered prefixes.
        assert_eq!(via(&[7018, 4134, 4808], "1.0.0.0/24"), None);
        assert_eq!(via(&[7018, 4134], "1.0.0.0/24"), None);
        assert_eq!(via(&[7018, 4134], "1.0.1.0/24"), Some(Asn(4134)));
    }
}
