//! Runs the whole pipeline and writes `release/` (published) and `report/` (CI artifact).
//!
//! Optional environment variables for development:
//! - `CN_IP_CACHE=.cache` keeps downloads on disk between runs;
//! - `CN_IP_AT=2026-09-30T08:00Z` rebuilds a past snapshot.

use std::path::{Path, PathBuf};
use std::{env, fs};

use anyhow::{Context, Result, bail};
use cn_mainland_ip::fetch::{self, Fetcher};
use jiff::Timestamp;
use tracing_subscriber::EnvFilter;

const RELEASE: &str = "release";
const REPORT: &str = "report";

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let snapshot = match env::var("CN_IP_AT") {
        Ok(at) => fetch::check_snapshot(at.parse().context("CN_IP_AT")?)?,
        Err(_) => fetch::latest_snapshot(Timestamp::now())?,
    };
    let fetcher = Fetcher::new(env::var_os("CN_IP_CACHE").map(PathBuf::from));

    let build = cn_mainland_ip::build(snapshot, &fetcher)?;
    write_files(Path::new(REPORT), &build.report.files)?;
    if !build.problems.is_empty() {
        bail!("not publishing:\n- {}", build.problems.join("\n- "));
    }
    write_files(Path::new(RELEASE), &build.artifacts.files)?;
    tracing::info!(
        ipv4 = build.artifacts.entries.v4,
        ipv6 = build.artifacts.entries.v6,
        "published to {RELEASE}/"
    );
    Ok(())
}

/// Writes each file next to its destination first and renames it into place.
fn write_files(root: &Path, files: &[(&str, impl AsRef<[u8]>)]) -> Result<()> {
    for (name, content) in files {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap_or(root))?;
        let mut partial = path.clone().into_os_string();
        partial.push(".tmp");
        fs::write(&partial, content)?;
        fs::rename(&partial, &path).with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}
