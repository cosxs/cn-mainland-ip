//! Surge `RULE-SET` file. Lines carry no `no-resolve`: users choose it on their `RULE-SET` line,
//! which they could not undo if it were written here.

use ipnet::IpNet;

use super::lines;
use crate::model::PerFamily;

pub(super) fn render(banner: &str, nets: &PerFamily<Vec<IpNet>>) -> String {
    format!("{banner}{}{}", lines(&nets.v4, "IP-CIDR,", ""), lines(&nets.v6, "IP-CIDR6,", ""))
}
