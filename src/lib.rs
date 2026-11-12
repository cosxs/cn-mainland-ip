//! Mainland China IP ranges derived from BGP routing data.
//!
//! A range is published when route collectors outside China see it reached through a mainland
//! backbone, or when nobody announces it and it is registered in CN. The pipeline is
//! `Inputs → Observations → Classification → Artifacts`: only [`fetch`] touches the network,
//! every other stage is a plain function of its inputs.

pub mod classify;
pub mod export;
pub mod fetch;
mod guard;
pub mod model;
pub mod nro;
pub mod params;
mod path;
mod ranges;
pub mod report;
pub mod rib;
pub mod rpki;

use std::io::BufReader;
use std::time::Instant;

use anyhow::{Context, Result};
use jiff::Timestamp;
use rayon::prelude::*;
use tracing::{info, warn};

use crate::export::{Artifacts, Header};
use crate::fetch::Fetcher;
use crate::nro::Registry;
use crate::params::{ASN_NAMES_URL, COLLECTORS, Collector};
use crate::report::{AsnNames, Manifest, Report};
use crate::rib::Observations;
use crate::rpki::{Dump, Roas};

/// Everything a build needs besides the RIB snapshots, already parsed.
pub struct Inputs {
    pub snapshot: Timestamp,
    pub registry: Registry,
    pub roas: Roas,
    pub names: AsnNames,
}

impl Inputs {
    pub fn fetch(snapshot: Timestamp, fetcher: &Fetcher) -> Result<Self> {
        let nro = fetch::nro_url(snapshot);
        let registry =
            fetch::retry(&nro, || Registry::parse(BufReader::new(fetcher.open(&nro)?))).context("NRO")?;
        let dumps = fetch::rpki_urls(snapshot)
            .iter()
            .map(|(_, url)| {
                fetch::retry(url, || Dump::parse(BufReader::new(fetcher.open(url)?))).context("RPKI")
            })
            .collect::<Result<Vec<_>>>()?;
        let roas = Roas::from_dumps(dumps)?;
        // Names only decorate the report, so their absence is not an error.
        let names = fetcher
            .open(ASN_NAMES_URL)
            .and_then(|r| AsnNames::parse(BufReader::new(r)))
            .unwrap_or_else(|e| {
                warn!("AS names unavailable, reports show numbers only: {e:#}");
                AsnNames::default()
            });
        info!(records = registry.records, roas = roas.len(), "inputs loaded");
        Ok(Self { snapshot, registry, roas, names })
    }
}

pub struct Build {
    pub artifacts: Artifacts,
    pub report: Report,
    /// Pre-publish problems; the artifacts must not be published unless this is empty.
    pub problems: Vec<String>,
}

pub fn build(snapshot: Timestamp, fetcher: &Fetcher) -> Result<Build> {
    let inputs = Inputs::fetch(snapshot, fetcher)?;
    // Every collector must succeed: a missing one could hide domestic paths only it sees.
    // Merged as they come, so that no more than a few RIBs are held at once.
    let (mut ribs, observations) = COLLECTORS
        .par_iter()
        .enumerate()
        .map(|(index, collector)| {
            observe(index, collector, &inputs, fetcher).map(|(at, o)| (vec![(index, at)], o))
        })
        .try_reduce(Default::default, |(mut a_ribs, a), (b_ribs, b)| {
            a_ribs.extend(b_ribs);
            Ok((a_ribs, a.merge(b)))
        })?;
    ribs.sort_unstable();
    let ribs: Vec<Timestamp> = ribs.into_iter().map(|(_, at)| at).collect();

    let classification = classify::run(&observations, &inputs.registry, &inputs.roas);
    let header = Header {
        snapshot,
        collectors: COLLECTORS.len(),
        nro: inputs.registry.published,
        rpki: inputs.roas.generated,
    };
    let artifacts = export::render(&classification.included, &header)?;
    let problems = guard::check(&inputs, &classification, &artifacts);
    let manifest = Manifest::new(&inputs, &ribs, &observations, &classification, &artifacts, &problems);
    let report = report::render(&manifest, &classification, &inputs.names)?;
    Ok(Build { artifacts, report, problems })
}

/// Parses the collector's RIB at the snapshot, or its newest one within `MAX_RIB_AGE` before it when
/// the collector published none, and returns when that RIB was taken.
fn observe(
    index: usize,
    collector: &Collector,
    inputs: &Inputs,
    fetcher: &Fetcher,
) -> Result<(Timestamp, Observations)> {
    let started = Instant::now();
    let mut at = inputs.snapshot;
    let observations = loop {
        let url = fetch::rib_url(collector, at);
        let result = fetch::retry(&url, || rib::observe(fetcher.open(&url)?, index, &inputs.registry));
        match result
            .as_ref()
            .err()
            .filter(|e| fetch::is_not_found(e))
            .and(fetch::earlier_rib(inputs.snapshot, at))
        {
            Some(earlier) => {
                warn!(collector = collector.name, %at, "no RIB, trying the one before");
                at = earlier;
            }
            None => break result.with_context(|| format!("collector {}", collector.name))?,
        }
    };
    let secs = started.elapsed().as_secs();
    info!(collector = collector.name, %at, routes = observations.routes.len(), secs, "RIB parsed");
    Ok((at, observations))
}
