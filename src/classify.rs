//! Longest-prefix matching over every announcement, and the table that turns the evidence for
//! each address range into a verdict.

use std::collections::{BTreeSet, HashMap};

use ipnet::IpNet;

use crate::model::{Asn, BgpStatus, Family, PerFamily, Reason, Verdict};
use crate::nro::Registry;
use crate::params::MIN_VISIBLE_PEER_ASNS;
use crate::ranges::{self, Cursor, Range};
use crate::rib::{Observations, Witnesses};
use crate::rpki::{Roas, Validity};

/// The decision table, one arm per rule. Only two kinds of range are published: those reached
/// through a mainland backbone, and those nobody announces that are registered in CN.
pub const fn decide(allocated: bool, bgp: BgpStatus, registered_cn: bool) -> Verdict {
    use BgpStatus as B;
    use Reason as R;
    match (allocated, bgp, registered_cn) {
        (false, _, _) => Verdict::Exclude(R::Unallocated),
        (true, B::Domestic, _) => Verdict::Include(R::BgpDomestic),
        (true, B::Unannounced, true) => Verdict::Include(R::RegistryFallback),
        (true, B::DomesticWeak, _) => Verdict::Exclude(R::NoDomesticPath),
        (true, B::Foreign, _) => Verdict::Exclude(R::ForeignOrigin),
        (true, B::Unannounced, false) => Verdict::Exclude(R::NoEvidence),
    }
}

/// Every route of one prefix that passed RPKI and visibility filtering.
#[derive(Clone, Debug)]
pub struct Announcement {
    pub prefix: IpNet,
    pub status: BgpStatus,
    pub origins: Vec<Asn>,
    pub domestic: Witnesses,
    pub domestic_collectors: u32,
}

/// One atomic range and the evidence that decided it.
#[derive(Clone, Debug)]
pub struct Decision {
    pub family: Family,
    pub range: Range,
    pub verdict: Verdict,
    pub status: BgpStatus,
    pub registered_cn: bool,
    /// Index into [`Classification::announcements`] of the longest matching prefix.
    pub announcement: Option<usize>,
}

#[derive(Debug, Default)]
pub struct Classification {
    pub included: PerFamily<Vec<Range>>,
    /// Decisions for CN-relevant ranges only: registered in CN or announced by a CN origin.
    pub decisions: Vec<Decision>,
    pub announcements: Vec<Announcement>,
    pub rpki_invalid_routes: usize,
    pub backbones: BTreeSet<Asn>,
}

pub fn run(observations: &Observations, registry: &Registry, roas: &Roas) -> Classification {
    let mut rpki_invalid_routes = 0;
    let mut by_prefix: HashMap<IpNet, Announcement> = HashMap::new();
    for (route, evidence) in &observations.routes {
        if evidence.peers.count() < MIN_VISIBLE_PEER_ASNS {
            continue;
        }
        if roas.validate(route.prefix, route.origin) == Validity::Invalid {
            rpki_invalid_routes += 1;
            continue;
        }
        let status = if evidence.domestic.count() > 0 {
            BgpStatus::Domestic
        } else if registry.is_cn_asn(route.origin) {
            BgpStatus::DomesticWeak
        } else {
            BgpStatus::Foreign
        };
        let announcement = by_prefix.entry(route.prefix).or_insert_with(|| Announcement {
            prefix: route.prefix,
            status,
            origins: Vec::new(),
            domestic: Witnesses::default(),
            domestic_collectors: 0,
        });
        announcement.status = announcement.status.max(status);
        announcement.origins.push(route.origin);
        announcement.domestic.merge(evidence.domestic);
        announcement.domestic_collectors |= evidence.domestic_collectors;
    }

    let mut announcements: Vec<Announcement> = by_prefix.into_values().collect();
    for announcement in &mut announcements {
        announcement.origins.sort_unstable();
    }
    // Less specific prefixes first at equal start, so nested prefixes stack up in order.
    announcements.sort_unstable_by_key(|a| {
        (Family::of(&a.prefix), *ranges::span(&a.prefix).start(), a.prefix.prefix_len())
    });

    let mut classification = Classification {
        rpki_invalid_routes,
        backbones: observations.backbones.clone(),
        ..Classification::default()
    };
    for family in Family::ALL {
        sweep(family, &announcements, registry, &mut classification);
    }
    classification.announcements = announcements;
    classification
}

/// Walks the address space of one family in atomic ranges, i.e. ranges in which neither the
/// longest matching prefix nor the registration changes, and applies [`decide`] to each.
fn sweep(family: Family, announcements: &[Announcement], registry: &Registry, out: &mut Classification) {
    let spans: Vec<(Range, usize)> = announcements
        .iter()
        .enumerate()
        .filter(|(_, a)| Family::of(&a.prefix) == family)
        .map(|(i, a)| (ranges::span(&a.prefix), i))
        .collect();
    let (allocated, cn) = (registry.allocated(family), registry.cn(family));

    let mut points: Vec<u128> = spans
        .iter()
        .map(|(range, _)| range)
        .chain(allocated)
        .chain(cn)
        .flat_map(|range| [Some(*range.start()), range.end().checked_add(1)])
        .flatten()
        .collect();
    points.sort_unstable();
    points.dedup();

    // Prefixes containing the current range, innermost last. CIDR prefixes nest or are
    // disjoint, so the top of the stack is always the longest match.
    let mut stack: Vec<(u128, usize)> = Vec::new();
    let mut spans = spans.iter().peekable();
    let (mut allocated, mut cn) = (Cursor::new(allocated), Cursor::new(cn));
    let included = &mut out.included[family];
    for window in points.windows(2) {
        let (start, end) = (window[0], window[1] - 1);
        while stack.last().is_some_and(|&(end, _)| end < start) {
            stack.pop();
        }
        while let Some((range, i)) = spans.next_if(|(range, _)| *range.start() == start) {
            stack.push((*range.end(), *i));
        }
        let is_allocated = allocated.contains(start);
        let registered_cn = cn.contains(start);
        let announcement = stack.last().map(|&(_, i)| i);
        let status = announcement.map_or(BgpStatus::Unannounced, |i| announcements[i].status);
        let verdict = decide(is_allocated, status, registered_cn);

        if verdict.is_included() {
            match included.last_mut() {
                Some(last) if *last.end() + 1 == start => *last = *last.start()..=end,
                _ => included.push(start..=end),
            }
        }
        if is_allocated && (registered_cn || status >= BgpStatus::DomesticWeak) {
            out.decisions.push(Decision {
                family,
                range: start..=end,
                verdict,
                status,
                registered_cn,
                announcement,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Reason as R;

    #[test]
    fn decision_table() {
        use BgpStatus::{Domestic, DomesticWeak, Foreign, Unannounced};
        let cases = [
            (false, Domestic, true, Verdict::Exclude(R::Unallocated)),
            (true, Domestic, false, Verdict::Include(R::BgpDomestic)),
            (true, Domestic, true, Verdict::Include(R::BgpDomestic)),
            (true, Unannounced, true, Verdict::Include(R::RegistryFallback)),
            (true, DomesticWeak, true, Verdict::Exclude(R::NoDomesticPath)),
            (true, Foreign, true, Verdict::Exclude(R::ForeignOrigin)),
            (true, Unannounced, false, Verdict::Exclude(R::NoEvidence)),
        ];
        for (allocated, status, cn, expected) in cases {
            assert_eq!(decide(allocated, status, cn), expected, "{allocated} {status:?} {cn}");
        }
    }
}
