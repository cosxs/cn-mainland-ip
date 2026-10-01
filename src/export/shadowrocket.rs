//! Shadowrocket `RULE-SET` file. Unlike Surge it has no `IP-CIDR6`: `IP-CIDR` takes both families.

use ipnet::IpNet;

use super::lines;
use crate::model::PerFamily;

pub(super) fn render(banner: &str, nets: &PerFamily<Vec<IpNet>>) -> String {
    format!("{banner}{}", lines(nets.v4.iter().chain(&nets.v6), "IP-CIDR,", ""))
}
