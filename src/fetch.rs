//! The only module that talks to the network. It builds archive URLs and hands out readers.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use jiff::{SignedDuration, Timestamp};

use crate::params::{
    Collector, NRO_ARCHIVE, Project, RIS_ARCHIVE, ROUTEVIEWS_ARCHIVE, RPKI_ARCHIVE, RPKI_TALS,
    SNAPSHOT_DELAY, SNAPSHOT_INTERVAL,
};

/// Opens URLs, decompressing by file extension.
#[derive(Debug, Default)]
pub struct Fetcher {
    cache: Option<PathBuf>,
}

impl Fetcher {
    /// With a cache directory, every file is downloaded once and read locally afterwards.
    pub fn new(cache: Option<PathBuf>) -> Self {
        Self { cache }
    }

    pub fn open(&self, url: &str) -> Result<Box<dyn Read + Send>> {
        let Some(dir) = &self.cache else {
            // Resumes with range requests when a long download drops.
            return Ok(oneio::get_resumable_http_reader(url)?);
        };
        let name = url.split_once("://").map_or(url, |(_, rest)| rest).replace('/', "_");
        let path = dir.join(&name);
        if !path.exists() {
            fs::create_dir_all(dir)?;
            let partial = dir.join(format!("{name}.part"));
            oneio::download(url, utf8(&partial)?)?;
            fs::rename(&partial, &path)?;
        }
        Ok(oneio::get_reader(utf8(&path)?)?)
    }
}

fn utf8(path: &Path) -> Result<&str> {
    path.to_str().with_context(|| format!("non UTF-8 path {}", path.display()))
}

/// The newest snapshot that every archive has had time to publish.
pub fn latest_snapshot(now: Timestamp) -> Result<Timestamp> {
    let ready = (now - SNAPSHOT_DELAY).as_second();
    Ok(Timestamp::from_second(ready - ready.rem_euclid(SNAPSHOT_INTERVAL.as_secs()))?)
}

/// A requested snapshot must be on the RIS schedule (00:00, 08:00, 16:00 UTC).
pub fn check_snapshot(at: Timestamp) -> Result<Timestamp> {
    ensure!(
        at.subsec_nanosecond() == 0 && at.as_second().rem_euclid(SNAPSHOT_INTERVAL.as_secs()) == 0,
        "snapshot {at} is not on the RIS schedule (00:00, 08:00 or 16:00 UTC)"
    );
    Ok(at)
}

pub fn rib_url(collector: &Collector, at: Timestamp) -> String {
    let (month, stamp) = (at.strftime("%Y.%m"), at.strftime("%Y%m%d.%H%M"));
    let name = collector.name;
    match collector.project {
        Project::Ris => format!("{RIS_ARCHIVE}/{name}/{month}/bview.{stamp}.gz"),
        Project::RouteViews => {
            format!("{ROUTEVIEWS_ARCHIVE}/{name}/bgpdata/{month}/RIBS/rib.{stamp}.bz2")
        }
    }
}

/// Registry and RPKI data come from the archive of the day before the snapshot:
/// always published by then, and fixed for a given snapshot.
fn previous_day(at: Timestamp) -> Timestamp {
    at - SignedDuration::from_hours(24)
}

pub fn nro_url(at: Timestamp) -> String {
    format!("{NRO_ARCHIVE}/{}/nro-delegated-stats", previous_day(at).strftime("%Y%m%d"))
}

pub fn rpki_urls(at: Timestamp) -> Vec<(&'static str, String)> {
    let day = previous_day(at).strftime("%Y/%m/%d").to_string();
    RPKI_TALS.iter().map(|&tal| (tal, format!("{RPKI_ARCHIVE}/{tal}.tal/{day}/output.json.xz"))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::COLLECTORS;

    fn at(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    #[test]
    fn snapshots_follow_the_ris_schedule() {
        assert_eq!(latest_snapshot(at("2026-09-30T10:00Z")).unwrap(), at("2026-09-30T08:00Z"));
        assert_eq!(latest_snapshot(at("2026-09-30T09:59Z")).unwrap(), at("2026-09-30T00:00Z"));
        assert!(check_snapshot(at("2026-09-30T16:00Z")).is_ok());
        assert!(check_snapshot(at("2026-09-30T12:00Z")).is_err());
    }

    #[test]
    fn archive_urls() {
        let snapshot = at("2026-09-30T08:00Z");
        let urls: Vec<String> = COLLECTORS.iter().map(|c| rib_url(c, snapshot)).collect();
        assert_eq!(urls[0], "https://data.ris.ripe.net/rrc25/2026.09/bview.20260930.0800.gz");
        assert_eq!(
            urls[1],
            "https://archive.routeviews.org/route-views.eqix/bgpdata/2026.09/RIBS/rib.20260930.0800.bz2"
        );
        assert_eq!(
            nro_url(snapshot),
            "https://ftp.ripe.net/pub/stats/ripencc/nro-stats/20260929/nro-delegated-stats"
        );
        assert_eq!(rpki_urls(snapshot)[1].1, "https://ftp.ripe.net/rpki/apnic.tal/2026/09/29/output.json.xz");
    }
}
