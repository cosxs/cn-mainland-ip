//! Built-in parameters. Changing any of them means a new release; git history is the change log.

use jiff::SignedDuration;

use crate::model::{Asn, PerFamily};

/// A route collector and the archive it publishes RIB snapshots to.
#[derive(Clone, Copy, Debug)]
pub struct Collector {
    pub name: &'static str,
    pub project: Project,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Project {
    Ris,
    RouteViews,
}

impl Collector {
    const fn ris(name: &'static str) -> Self {
        Self { name, project: Project::Ris }
    }

    const fn route_views(name: &'static str) -> Self {
        Self { name, project: Project::RouteViews }
    }
}

/// Chosen by evaluating all 79 active collectors on 2026-09-30: together these 14 saw every
/// domestic path that any collector saw. Every one must succeed, otherwise nothing is published.
pub const COLLECTORS: [Collector; 14] = [
    Collector::ris("rrc25"),
    Collector::route_views("route-views.eqix"),
    Collector::ris("rrc21"),
    Collector::route_views("route-views8"),
    Collector::ris("rrc11"),
    Collector::ris("rrc00"),
    Collector::route_views("route-views.sg"),
    Collector::ris("rrc20"),
    Collector::route_views("hkix.hkg"),
    Collector::route_views("route-views.linx"),
    Collector::route_views("route-views.perth"),
    Collector::route_views("route-views3"),
    Collector::ris("rrc05"),
    Collector::route_views("amsix.ams"),
];

/// Mainland networks reach the rest of the world through these backbones: China Telecom
/// (163, CN2), China Unicom (169, CUII), China Mobile (CMNET), CERNET and CSTNET.
pub const BACKBONE_ASNS: [Asn; 8] =
    [Asn(4134), Asn(4809), Asn(4837), Asn(9929), Asn(9808), Asn(4538), Asn(23911), Asn(7497)];

/// Distinct peer ASNs that must see a route before it counts; 1 keeps every route.
/// Visibility is tracked up to two peers, see `rib::Witnesses`.
pub const MIN_VISIBLE_PEER_ASNS: usize = 1;
const _: () = assert!(MIN_VISIBLE_PEER_ASNS <= 2);

/// More specific prefixes do not take part in the decision.
pub const MAX_PREFIX_LEN: PerFamily<u8> = PerFamily { v4: 24, v6: 48 };

/// RIS dumps RIBs every 8 hours and RouteViews every 2 hours, so snapshots follow RIS.
pub const SNAPSHOT_INTERVAL: SignedDuration = SignedDuration::from_hours(8);
/// Time for a snapshot to be completely published to every archive.
pub const SNAPSHOT_DELAY: SignedDuration = SignedDuration::from_hours(2);

/// Freshness limits relative to the snapshot.
pub const MAX_AGE_NRO: SignedDuration = SignedDuration::from_hours(72);
pub const MAX_AGE_RPKI: SignedDuration = SignedDuration::from_hours(48);

/// About 80% of the size on 2026-09-30 (6,270 IPv4 and 3,519 IPv6 entries).
pub const MIN_ENTRIES: PerFamily<usize> = PerFamily { v4: 5_000, v6: 2_800 };

/// Surge limit for one rule set.
pub const SURGE_MAX_ENTRIES: usize = 1_000_000;

pub const RIS_ARCHIVE: &str = "https://data.ris.ripe.net";
pub const ROUTEVIEWS_ARCHIVE: &str = "https://archive.routeviews.org";
pub const NRO_ARCHIVE: &str = "https://ftp.ripe.net/pub/stats/ripencc/nro-stats";
pub const RPKI_ARCHIVE: &str = "https://ftp.ripe.net/rpki";
pub const RPKI_TALS: [&str; 5] = ["afrinic", "apnic", "arin", "lacnic", "ripencc"];
/// Optional: only used to show AS names in reports.
pub const ASN_NAMES_URL: &str = "https://ftp.ripe.net/ripe/asnames/asn.txt";
