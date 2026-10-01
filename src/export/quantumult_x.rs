//! Quantumult X filter resource for `[filter_remote]`. Every line must name a policy: `direct` is
//! what this list is for, and `force-policy` on the subscription line can still override it.

use ipnet::IpNet;

use super::lines;
use crate::model::PerFamily;

pub(super) fn render(banner: &str, nets: &PerFamily<Vec<IpNet>>) -> String {
    format!(
        "{banner}{}{}",
        lines(&nets.v4, "ip-cidr, ", ", direct"),
        lines(&nets.v6, "ip6-cidr, ", ", direct")
    )
}
