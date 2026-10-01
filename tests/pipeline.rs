//! End-to-end run on a synthetic RIB with one route per classification rule.
#![allow(clippy::unwrap_used)] // helpers below are test code too

use std::io::Cursor;

use bgpkit_parser::encoder::MrtRibEncoder;
use bgpkit_parser::models::{AsPath, BgpElem, ElemType};
use cn_mainland_ip::export::{
    self, EGERN, Header, LOON, MIHOMO_YAML, QUANTUMULT_X, SHADOWROCKET, SING_BOX_JSON, SURGE,
};
use cn_mainland_ip::model::Asn;
use cn_mainland_ip::nro::Registry;
use cn_mainland_ip::rpki::Roas;
use cn_mainland_ip::{classify, rib};

/// AS4134 is a backbone; AS4808, AS37963 and AS45102 are CN networks; the rest are foreign.
const NRO: &str = "\
2|nro|20260929|14|19821213|20260929|+0000
apnic|CN|asn|4134|1|20020801|allocated|A1|e-stats
apnic|CN|asn|4808|1|20020801|allocated|A2|e-stats
apnic|CN|asn|37963|1|20060725|allocated|A3|e-stats
apnic|CN|asn|45102|1|20080618|allocated|A3|e-stats
arin|US|asn|2914|1|19940105|assigned|B1|e-stats
arin|US|asn|3356|1|19941020|assigned|B2|e-stats
arin|US|asn|7018|1|19960628|assigned|B3|e-stats
apnic|CN|ipv4|1.0.0.0|65536|20110414|allocated|A2|e-stats
arin|SG|ipv4|8.128.0.0|65536|20200302|allocated|A3|e-stats
apnic|CN|ipv4|42.0.0.0|65536|20100916|allocated|A2|e-stats
apnic|CN|ipv4|110.99.0.0|65536|20100922|allocated|A2|e-stats
apnic|SG|ipv4|147.139.0.0|65536|20170420|allocated|A3|e-stats
arin|US|ipv4|12.0.0.0|16777216|19830801|assigned|B3|e-stats
apnic|CN|ipv6|240e::|20|20150112|allocated|A1|e-stats
";

fn announce(path: &[u32], prefix: &str) -> BgpElem {
    let peer = path[0];
    BgpElem {
        elem_type: ElemType::ANNOUNCE,
        peer_ip: format!("192.0.2.{}", peer % 250).parse().unwrap(),
        peer_asn: peer.into(),
        prefix: prefix.parse().unwrap(),
        as_path: Some(AsPath::from_sequence(path)),
        ..Default::default()
    }
}

#[test]
fn routing_cases() {
    let registry = Registry::parse(NRO.as_bytes()).unwrap();
    let routes = [
        // Reached through a backbone: included.
        announce(&[3356, 4134, 4808], "1.0.0.0/16"),
        // A CN origin seen only through foreign transit: carved out of the /16 above.
        announce(&[3356, 45102], "1.0.128.0/24"),
        // Registered in SG but behind a CN network behind a backbone (Aliyun `8.x`): included.
        announce(&[3356, 4134, 4808, 37963], "8.128.0.0/16"),
        // Backbone directly next to an origin whose space is registered abroad: overseas PoP.
        announce(&[2914, 4134, 45102], "147.139.0.0/18"),
        // CN-registered space announced by a foreign origin: excluded.
        announce(&[2914, 3356], "110.99.0.0/16"),
        // Foreign space, foreign origin: excluded.
        announce(&[3356, 7018], "12.0.0.0/8"),
        // Backbone origin inside its CN allocation; the rest of the /20 falls back to the registry.
        announce(&[3356, 4134], "240e::/24"),
        // 42.0.0.0/16 is registered in CN and never announced: registry fallback.
    ];
    let mut encoder = MrtRibEncoder::new();
    for route in &routes {
        encoder.process_elem(route).unwrap();
    }
    let mrt = encoder.export_bytes().unwrap();

    let observations = rib::observe(Cursor::new(mrt.to_vec()), 0, &registry).unwrap();
    let classification = classify::run(&observations, &registry, &Roas::default());
    assert!(classification.backbones.contains(&Asn(4134)));

    let header = Header {
        snapshot: "2026-09-30T08:00Z".parse().unwrap(),
        collectors: 1,
        nro: registry.published,
        rpki: None,
    };
    let artifacts = export::render(&classification.included, &header).unwrap();
    let text = |path| std::str::from_utf8(artifacts.file(path).unwrap()).unwrap();
    insta::assert_snapshot!("surge", text(SURGE));
    assert_eq!(text(LOON), text(SURGE));
    insta::assert_snapshot!("shadowrocket", text(SHADOWROCKET));
    insta::assert_snapshot!("quantumult-x", text(QUANTUMULT_X));
    insta::assert_snapshot!("mihomo", text(MIHOMO_YAML));
    insta::assert_snapshot!("sing-box", text(SING_BOX_JSON));
    insta::assert_snapshot!("egern", text(EGERN));
}
