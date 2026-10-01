//! Egern rule set. Like the other formats it leaves out `no_resolve`, so Egern resolves domain
//! requests and matches their addresses.

use ipnet::IpNet;

use super::yaml_list;
use crate::model::PerFamily;

pub(super) fn render(banner: &str, nets: &PerFamily<Vec<IpNet>>) -> String {
    format!("{banner}ip_cidr_set:\n{}ip_cidr6_set:\n{}", yaml_list(&nets.v4), yaml_list(&nets.v6))
}
