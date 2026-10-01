//! Streams one collector's RIB snapshot into [`Observations`].

use std::collections::{BTreeSet, HashMap};
use std::io::Read;

use anyhow::Result;
use bgpkit_parser::BgpkitParser;
use bgpkit_parser::models::{BgpElem, ElemType};
use ipnet::IpNet;

use crate::model::{Asn, Family};
use crate::nro::Registry;
use crate::params::{COLLECTORS, MAX_PREFIX_LEN};
use crate::path;

// `Evidence::domestic_collectors` has one bit per collector.
const _: () = assert!(COLLECTORS.len() <= u32::BITS as usize);

/// A prefix as announced by one origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Route {
    pub prefix: IpNet,
    pub origin: Asn,
}

/// Up to two distinct peers that saw something: enough to tell "one" from "several".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Witnesses {
    first: Option<Asn>,
    more: bool,
}

impl Witnesses {
    pub fn add(&mut self, peer: Asn) {
        match self.first {
            None => self.first = Some(peer),
            Some(first) if first != peer => self.more = true,
            Some(_) => {}
        }
    }

    pub fn merge(&mut self, other: Self) {
        if let Some(peer) = other.first {
            self.add(peer);
        }
        self.more |= other.more;
    }

    /// 0, 1, or 2 meaning "two or more".
    pub fn count(self) -> usize {
        usize::from(self.first.is_some()) + usize::from(self.more)
    }

    /// The peer, if exactly one saw it.
    pub fn single(self) -> Option<Asn> {
        self.first.filter(|_| !self.more)
    }
}

/// What the collectors saw of one route.
#[derive(Clone, Copy, Debug, Default)]
pub struct Evidence {
    pub peers: Witnesses,
    /// Peers with a domestic path.
    pub domestic: Witnesses,
    /// Bit `i` set: collector `i` of `params::COLLECTORS` saw a domestic path.
    pub domestic_collectors: u32,
}

impl Evidence {
    fn merge(&mut self, other: Self) {
        self.peers.merge(other.peers);
        self.domestic.merge(other.domestic);
        self.domestic_collectors |= other.domestic_collectors;
    }
}

/// Routes seen by one or more collectors. Merging is associative, so collectors can be
/// processed in parallel and reduced in any order.
#[derive(Debug, Default)]
pub struct Observations {
    pub routes: HashMap<Route, Evidence>,
    /// Backbones that appeared on at least one domestic path.
    pub backbones: BTreeSet<Asn>,
}

impl Observations {
    #[must_use]
    pub fn merge(mut self, mut other: Self) -> Self {
        if self.routes.len() < other.routes.len() {
            std::mem::swap(&mut self, &mut other);
        }
        for (route, evidence) in other.routes {
            self.routes.entry(route).or_default().merge(evidence);
        }
        self.backbones.append(&mut other.backbones);
        self
    }

    fn record(&mut self, collector_index: usize, elem: &BgpElem, registry: &Registry) {
        let prefix = elem.prefix.prefix;
        let len = prefix.prefix_len();
        if elem.elem_type != ElemType::ANNOUNCE || len == 0 || len > MAX_PREFIX_LEN[Family::of(&prefix)] {
            return;
        }
        let peer = Asn(elem.peer_asn.to_u32());
        let as_path: Option<Vec<Asn>> = elem
            .as_path
            .as_ref()
            .and_then(|p| p.to_u32_vec_opt(true))
            .map(|p| p.into_iter().map(Asn).collect());

        // Paths with AS_SETs still announce the prefix, but prove nothing about the route.
        let via = as_path.as_deref().and_then(|p| path::domestic_via(p, &prefix, registry));
        let origins: Vec<Asn> = match &as_path {
            Some(p) => p.last().copied().into_iter().collect(),
            None => elem.origin_asns.iter().flatten().map(|a| Asn(a.to_u32())).collect(),
        };
        for origin in origins.into_iter().filter(|o| o.is_public()) {
            let evidence = self.routes.entry(Route { prefix, origin }).or_default();
            evidence.peers.add(peer);
            if let Some(backbone) = via {
                evidence.domestic.add(peer);
                evidence.domestic_collectors |= 1 << collector_index;
                self.backbones.insert(backbone);
            }
        }
    }
}

/// Reads a whole MRT RIB dump. Read errors, including a truncated download, fail the collector.
pub fn observe(reader: impl Read, collector_index: usize, registry: &Registry) -> Result<Observations> {
    let mut observations = Observations::default();
    for elem in BgpkitParser::from_reader(reader).into_fallible_elem_iter() {
        observations.record(collector_index, &elem?, registry);
    }
    Ok(observations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witnesses_saturate_at_two() {
        let mut w = Witnesses::default();
        assert_eq!((w.count(), w.single()), (0, None));
        w.add(Asn(1));
        w.add(Asn(1));
        assert_eq!((w.count(), w.single()), (1, Some(Asn(1))));
        let mut other = Witnesses::default();
        other.add(Asn(2));
        w.merge(other);
        assert_eq!((w.count(), w.single()), (2, None));
    }
}
