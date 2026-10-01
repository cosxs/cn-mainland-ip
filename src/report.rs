//! Maintainer report. It is kept as a CI artifact and never published.

use std::collections::{BTreeMap, HashMap};
use std::io::BufRead;
use std::iter;

use anyhow::Result;
use jiff::Timestamp;
use serde::Serialize;

use crate::Inputs;
use crate::classify::{Announcement, Classification};
use crate::export::Artifacts;
use crate::fetch;
use crate::model::{Asn, BgpStatus, Family, PerFamily};
use crate::params::COLLECTORS;
use crate::ranges::{self, Range};
use crate::rib::{Observations, Witnesses};

/// AS names from RIPE NCC's `asn.txt`; empty when that optional source is unavailable.
#[derive(Debug, Default)]
pub struct AsnNames(HashMap<Asn, String>);

impl AsnNames {
    /// Lines look like `4134 CHINANET-BACKBONE - No.31,Jin-rong Street, CN`.
    pub fn parse(reader: impl BufRead) -> Result<Self> {
        let mut names = HashMap::new();
        for line in reader.lines() {
            let line = line?;
            if let Some((asn, rest)) = line.split_once(' ')
                && let Ok(asn) = asn.parse()
            {
                let handle = rest.split(" - ").next().unwrap_or(rest);
                names.insert(Asn(asn), handle.to_owned());
            }
        }
        Ok(Self(names))
    }

    fn label(&self, asn: Asn) -> String {
        self.0.get(&asn).map_or_else(|| asn.to_string(), |name| format!("{asn} {name}"))
    }
}

/// Inputs and outcome of one build.
#[derive(Debug, Serialize)]
pub struct Manifest {
    pub snapshot: Timestamp,
    pub collectors: Vec<Source>,
    pub nro: Source,
    pub nro_records: usize,
    pub rpki: Vec<Source>,
    pub rpki_generated: Option<Timestamp>,
    pub roas: usize,
    pub routes: usize,
    pub rpki_invalid_routes: usize,
    pub entries: PerFamily<usize>,
    pub volume: PerFamily<u128>,
    pub problems: Vec<String>,
}

impl Manifest {
    pub fn new(
        inputs: &Inputs,
        observations: &Observations,
        classification: &Classification,
        artifacts: &Artifacts,
        problems: &[String],
    ) -> Self {
        let snapshot = inputs.snapshot;
        let source = |name: &str, url: String| Source { name: name.to_owned(), url };
        Self {
            snapshot,
            collectors: COLLECTORS.iter().map(|c| source(c.name, fetch::rib_url(c, snapshot))).collect(),
            nro: source("nro", fetch::nro_url(snapshot)),
            nro_records: inputs.registry.records,
            rpki: fetch::rpki_urls(snapshot).into_iter().map(|(tal, url)| source(tal, url)).collect(),
            rpki_generated: inputs.roas.generated,
            roas: inputs.roas.len(),
            routes: observations.routes.len(),
            rpki_invalid_routes: classification.rpki_invalid_routes,
            entries: artifacts.entries,
            volume: PerFamily::from_fn(|family| volume(&classification.included[family], family)),
            problems: problems.to_vec(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Source {
    pub name: String,
    pub url: String,
}

pub struct Report {
    pub files: Vec<(&'static str, String)>,
}

pub fn render(manifest: &Manifest, classification: &Classification, names: &AsnNames) -> Result<Report> {
    Ok(Report {
        files: vec![
            ("manifest.json", serde_json::to_string_pretty(manifest)? + "\n"),
            ("reasons.tsv", reasons(classification)),
            ("evidence.tsv", evidence(classification, names)),
            ("collectors.tsv", collectors(classification)),
        ],
    })
}

fn table(header: &str, rows: impl Iterator<Item = String>) -> String {
    iter::once(format!("{header}\n")).chain(rows.map(|row| row + "\n")).collect()
}

/// Reports count IPv4 addresses and IPv6 /48s.
const VOLUME_UNIT: PerFamily<u8> = PerFamily { v4: 32, v6: 48 };

fn volume(ranges: &[Range], family: Family) -> u128 {
    ranges::size(ranges, family, VOLUME_UNIT[family])
}

/// Range count and volume per reason code.
fn reasons(classification: &Classification) -> String {
    let mut totals: BTreeMap<_, (usize, u128)> = BTreeMap::new();
    for decision in &classification.decisions {
        let (family, verdict) = (decision.family, decision.verdict);
        let (ranges, volume) =
            totals.entry((family.name(), verdict.label(), verdict.reason().code())).or_default();
        *ranges += 1;
        *volume += self::volume(std::slice::from_ref(&decision.range), family);
    }
    table(
        "family\tverdict\treason\tranges\tvolume",
        totals.into_iter().map(|((family, verdict, reason), (ranges, volume))| {
            format!("{family}\t{verdict}\t{reason}\t{ranges}\t{volume}")
        }),
    )
}

/// One row per CN-relevant atomic range, with the evidence behind its verdict.
fn evidence(classification: &Classification, names: &AsnNames) -> String {
    let route = |announcement: &Announcement| {
        let origins: Vec<String> = announcement.origins.iter().map(|&o| names.label(o)).collect();
        format!(
            "{}\t{}\t{}\t{}",
            announcement.prefix,
            origins.join("; "),
            witness(announcement.domestic),
            collector_names(announcement.domestic_collectors)
        )
    };
    table(
        "first\tlast\tverdict\treason\tstatus\tregistered_cn\tprefix\torigins\tdomestic_peer\tdomestic_collectors",
        classification.decisions.iter().map(|decision| {
            let announcement = decision.announcement.map(|i| &classification.announcements[i]);
            format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                decision.family.addr(*decision.range.start()),
                decision.family.addr(*decision.range.end()),
                decision.verdict.label(),
                decision.verdict.reason().code(),
                decision.status.code(),
                decision.registered_cn,
                announcement.map_or_else(|| "-\t-\t-\t-".to_owned(), route),
            )
        }),
    )
}

/// How many domestic prefixes each collector alone proves; zero for a long time means it can go.
fn collectors(classification: &Classification) -> String {
    let sole = |i: usize| {
        classification
            .announcements
            .iter()
            .filter(|a| a.status == BgpStatus::Domestic && a.domestic_collectors == 1 << i)
            .count()
    };
    table(
        "collector\tsole_domestic_prefixes",
        COLLECTORS.iter().enumerate().map(|(i, collector)| format!("{}\t{}", collector.name, sole(i))),
    )
}

fn witness(witnesses: Witnesses) -> String {
    match (witnesses.count(), witnesses.single()) {
        (0, _) => "-".to_owned(),
        (_, Some(peer)) => peer.to_string(),
        _ => "2+".to_owned(),
    }
}

fn collector_names(mask: u32) -> String {
    let names: Vec<&str> =
        COLLECTORS.iter().enumerate().filter(|&(i, _)| mask & (1 << i) != 0).map(|(_, c)| c.name).collect();
    if names.is_empty() { "-".to_owned() } else { names.join(",") }
}
