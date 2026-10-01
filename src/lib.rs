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
            Registry::parse(BufReader::new(fetcher.open(&nro)?)).with_context(|| format!("NRO {nro}"))?;
        let dumps = fetch::rpki_urls(snapshot)
            .iter()
            .map(|(_, url)| {
                Dump::parse(BufReader::new(fetcher.open(url)?)).with_context(|| format!("RPKI {url}"))
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
    let observations = COLLECTORS
        .par_iter()
        .enumerate()
        .map(|(index, collector)| observe(index, collector, &inputs, fetcher))
        .try_reduce(Observations::default, |a, b| Ok(a.merge(b)))?;

    let classification = classify::run(&observations, &inputs.registry, &inputs.roas);
    let header = Header {
        snapshot,
        collectors: COLLECTORS.len(),
        nro: inputs.registry.published,
        rpki: inputs.roas.generated,
    };
    let artifacts = export::render(&classification.included, &header)?;
    let problems = guard::check(&inputs, &classification, &artifacts);
    let manifest = Manifest::new(&inputs, &observations, &classification, &artifacts, &problems);
    let report = report::render(&manifest, &classification, &inputs.names)?;
    Ok(Build { artifacts, report, problems })
}

fn observe(index: usize, collector: &Collector, inputs: &Inputs, fetcher: &Fetcher) -> Result<Observations> {
    let url = fetch::rib_url(collector, inputs.snapshot);
    let started = Instant::now();
    let observations = rib::observe(fetcher.open(&url)?, index, &inputs.registry)
        .with_context(|| format!("collector {}: {url}", collector.name))?;
    let secs = started.elapsed().as_secs();
    info!(collector = collector.name, routes = observations.routes.len(), secs, "RIB parsed");
    Ok(observations)
}
