//! The only module that talks to the network. It builds archive URLs and hands out readers.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use jiff::{SignedDuration, Timestamp};
use oneio::OneIoError;

use crate::params::{
    Collector, DOWNLOAD_ATTEMPTS, NRO_ARCHIVE, Project, RETRY_DELAY, RIS_ARCHIVE, ROUTEVIEWS_ARCHIVE,
    RPKI_ARCHIVE, RPKI_TALS, SNAPSHOT_DELAY, SNAPSHOT_INTERVAL,
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

/// Runs `read` until it succeeds or the file turns out to be missing, at most `DOWNLOAD_ATTEMPTS`
/// times. `read` must open `url` itself,
/// so that a stream that broke half way is downloaded again from the start.
pub fn retry<T>(url: &str, read: impl FnMut() -> Result<T>) -> Result<T> {
    retry_after(RETRY_DELAY, url, read)
}

fn retry_after<T>(delay: Duration, url: &str, mut read: impl FnMut() -> Result<T>) -> Result<T> {
    for attempt in 1.. {
        match read() {
            Err(e) if attempt < DOWNLOAD_ATTEMPTS && !is_not_found(&e) => {
                tracing::warn!(url, attempt, "retrying: {e:#}");
                thread::sleep(delay * attempt);
            }
            result => return result.with_context(|| format!("{url} (attempt {attempt})")),
        }
    }
    unreachable!("the last attempt returns")
}

/// Whether `error` comes from a 404: the archive has not published the file, and asking again
/// will not help.
pub fn is_not_found(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let Some(OneIoError::Network(source) | OneIoError::NetworkWithContext { source, .. }) =
            cause.downcast_ref::<OneIoError>()
        else {
            return false;
        };
        source.downcast_ref::<reqwest::Error>().and_then(reqwest::Error::status)
            == Some(reqwest::StatusCode::NOT_FOUND)
    })
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
    fn retry_until_success_or_the_last_attempt() {
        let mut calls = 0;
        assert_eq!(
            retry_after(Duration::ZERO, "u", || {
                calls += 1;
                if calls < 2 {
                    anyhow::bail!("drop")
                }
                Ok(calls)
            })
            .unwrap(),
            2
        );
        calls = 0;
        assert!(
            retry_after::<()>(Duration::ZERO, "u", || {
                calls += 1;
                anyhow::bail!("down")
            })
            .is_err()
        );
        assert_eq!(calls, DOWNLOAD_ATTEMPTS);
    }

    /// Serves one HTTP response with `status` on localhost and returns its URL.
    fn serve_once(status: &'static str) -> String {
        use std::io::{BufRead as _, BufReader, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/rib.gz", listener.local_addr().unwrap());
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap() > 2 {
                line.clear();
            }
            let response = format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
            reader.get_mut().write_all(response.as_bytes()).unwrap();
        });
        url
    }

    #[test]
    fn missing_files_are_told_apart_from_other_failures() {
        let open = |url: String| Fetcher::default().open(&url).map(drop).unwrap_err();
        assert!(is_not_found(&open(serve_once("404 Not Found")).context("collector rrc25")));
        assert!(!is_not_found(&open(serve_once("503 Service Unavailable"))));
        assert!(!is_not_found(&anyhow::anyhow!("connection reset")));
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
