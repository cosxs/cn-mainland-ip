//! Pre-publish checks. Every problem is reported, not only the first one.

use crate::Inputs;
use crate::classify::Classification;
use crate::export::Artifacts;
use crate::model::Family;
use crate::params::{BACKBONE_ASNS, MAX_AGE_NRO, MAX_AGE_RPKI, MIN_ENTRIES, SURGE_MAX_ENTRIES};

/// Returns the problems found; publishing is allowed only when there are none.
pub fn check(inputs: &Inputs, classification: &Classification, artifacts: &Artifacts) -> Vec<String> {
    let mut problems = Vec::new();
    let mut fail = |problem: String| problems.push(problem);
    let (snapshot, registry, roas) = (inputs.snapshot, &inputs.registry, &inputs.roas);

    let nro_age = snapshot.duration_since(registry.published);
    if nro_age > MAX_AGE_NRO {
        fail(format!("NRO data is {nro_age:#} older than the snapshot"));
    }
    if roas.is_empty() {
        fail("no ROAs loaded".into());
    }
    if let Some(generated) = roas.generated.filter(|&g| snapshot.duration_since(g) > MAX_AGE_RPKI) {
        fail(format!("RPKI data generated at {generated} is too old"));
    }

    // A backbone that disappears would silently turn its customers' space into "no domestic path".
    for asn in BACKBONE_ASNS {
        if !registry.is_cn_asn(asn) {
            fail(format!("backbone {asn} is no longer registered in CN"));
        }
        if !classification.backbones.contains(&asn) {
            fail(format!("backbone {asn} appeared on no domestic path"));
        }
    }

    let entries = artifacts.entries;
    for family in Family::ALL {
        let (count, min) = (entries[family], MIN_ENTRIES[family]);
        if count < min {
            fail(format!("only {count} {} entries, expected at least {min}", family.name()));
        }
    }
    let total = entries.v4 + entries.v6;
    if total > SURGE_MAX_ENTRIES {
        fail(format!("{total} entries exceed the Surge limit of {SURGE_MAX_ENTRIES}"));
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::{self, Header};
    use crate::model::{Asn, PerFamily};
    use crate::nro::tests::sample;
    use crate::report::AsnNames;
    use crate::rpki::{Dump, Roas};

    #[test]
    fn reports_every_problem() {
        let dump = r#"{ "metadata": { "generated": 1700000000 }, "roas": [] }"#;
        let inputs = Inputs {
            snapshot: "2026-09-30T08:00Z".parse().unwrap(),
            registry: sample(),
            roas: Roas::from_dumps([Dump::parse(dump.as_bytes()).unwrap()]).unwrap(),
            names: AsnNames::default(),
        };
        let classification = Classification { backbones: [Asn(4134)].into(), ..Classification::default() };
        let header =
            Header { snapshot: inputs.snapshot, collectors: 1, nro: inputs.registry.published, rpki: None };
        let artifacts = export::render(&PerFamily::default(), &header).unwrap();

        let problems = check(&inputs, &classification, &artifacts);
        let count = |needle: &str| problems.iter().filter(|p| p.contains(needle)).count();
        assert_eq!(count("no ROAs loaded"), 1);
        assert_eq!(count("RPKI data generated"), 1);
        assert_eq!(count("no longer registered in CN"), 7, "the sample registry only knows AS4134");
        assert_eq!(count("appeared on no domestic path"), 7);
        assert_eq!(count("entries, expected at least"), 2);
    }
}
