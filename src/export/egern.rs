//! Egern rule set. Like the other formats it leaves out `no_resolve`, so Egern resolves domain
//! requests and matches their addresses. A family with no entries gets no key, so the single-family
//! files hold no empty (null) list.

use ipnet::IpNet;

use super::yaml_list;
use crate::model::PerFamily;

pub(super) fn render(banner: &str, nets: &PerFamily<Vec<IpNet>>) -> String {
    let set = |key: &str, items: &[IpNet]| {
        if items.is_empty() { String::new() } else { format!("{key}:\n{}", yaml_list(items)) }
    };
    format!("{banner}{}{}", set("ip_cidr_set", &nets.v4), set("ip_cidr6_set", &nets.v6))
}
