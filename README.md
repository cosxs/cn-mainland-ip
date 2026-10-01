# cn-mainland-ip

基于 BGP 路由数据生成的中国大陆 IP 地址列表，每天自动更新，用于代理分流。

## 订阅

产物在 `main` 分支的 `release/` 目录，按客户端分目录：

| 文件 | 内容 |
| --- | --- |
| `surge/cn.list` | Surge 规则集（`IP-CIDR` / `IP-CIDR6`） |
| `loon/cn.list` | Loon 远程规则，内容与 `surge/cn.list` 相同 |
| `shadowrocket/cn.list` | Shadowrocket 规则集（IPv4 和 IPv6 都用 `IP-CIDR`） |
| `quantumult-x/cn.list` | Quantumult X 分流资源（`ip-cidr` / `ip6-cidr`，策略 `direct`） |
| `mihomo/cn.mrs` | mihomo 二进制规则集（`behavior: ipcidr`，`format: mrs`） |
| `mihomo/cn.yaml` | mihomo 文本规则集（`behavior: ipcidr`，`format: yaml`） |
| `sing-box/cn.srs` | sing-box 二进制规则集（`format: binary`） |
| `sing-box/cn.json` | sing-box 源格式规则集（`format: source`） |
| `egern/cn.yaml` | Egern 规则集（`ip_cidr_set` / `ip_cidr6_set`） |
| `text/cn.txt` | 纯 CIDR 列表，每行一个，先 IPv4 后 IPv6 |

同一客户端的二进制和文本规则集内容相同，二进制的体积更小、加载更快。

每次更新也会在 [Releases](https://github.com/cosxs/cn-mainland-ip/releases) 发布一份，版本号是数据快照的时间（如 `20261001.0800`，UTC），文件以目录名命名，例如 `surge/cn.list` 对应 `https://github.com/cosxs/cn-mainland-ip/releases/latest/download/surge.list`。

规则都放在域名规则之后、兜底规则之前。规则集里不写 `no-resolve`，由你在规则那一行决定。

**Surge**

```
RULE-SET,https://raw.githubusercontent.com/cosxs/cn-mainland-ip/main/release/surge/cn.list,DIRECT
```

**Loon**

```
[Remote Rule]
https://raw.githubusercontent.com/cosxs/cn-mainland-ip/main/release/loon/cn.list,policy=DIRECT,tag=cn-mainland-ip,enabled=true
```

**Shadowrocket**

```
[Rule]
RULE-SET,https://raw.githubusercontent.com/cosxs/cn-mainland-ip/main/release/shadowrocket/cn.list,DIRECT
```

**Quantumult X**

```
[filter_remote]
https://raw.githubusercontent.com/cosxs/cn-mainland-ip/main/release/quantumult-x/cn.list, tag=cn-mainland-ip, force-policy=direct, enabled=true
```

Quantumult X 要求每行都写策略，文件里写的是 `direct`；`force-policy` 可以改成别的策略。

**mihomo**

```yaml
rule-providers:
  cn-mainland-ip:
    type: http
    behavior: ipcidr
    format: mrs
    url: https://raw.githubusercontent.com/cosxs/cn-mainland-ip/main/release/mihomo/cn.mrs
    path: ./ruleset/cn-mainland-ip.mrs
    interval: 86400

rules:
  - RULE-SET,cn-mainland-ip,DIRECT
```

`.mrs` 需要 mihomo 1.18.7 及以上；更早的版本改用 `format: yaml` 和 `cn.yaml`。

**sing-box**

```json
{
  "route": {
    "rule_set": [
      {
        "type": "remote",
        "tag": "cn-mainland-ip",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/cosxs/cn-mainland-ip/main/release/sing-box/cn.srs"
      }
    ],
    "rules": [
      { "rule_set": "cn-mainland-ip", "outbound": "direct" }
    ]
  }
}
```

两种格式都支持 sing-box 1.8.0 及以上，想看内容可以改用 `"format": "source"` 和 `cn.json`。sing-box 只拿目标 IP 匹配 `ip_cidr`，域名请求要先经过 `{ "action": "resolve" }` 规则解析才会命中，作用相当于 Surge/mihomo 不加 `no-resolve`。

**Egern**

```yaml
rules:
  - rule_set:
      match: https://raw.githubusercontent.com/cosxs/cn-mainland-ip/main/release/egern/cn.yaml
      policy: DIRECT
```

大陆直连 `raw.githubusercontent.com` 可能不稳定。Surge 首次下载失败时可以先通过代理下载一次；mihomo 可以在 provider 里加 `proxy: <代理组>`；sing-box 可以用 `download_detour`（1.14 起改为 `http_client`）指定经代理下载。

## 判定方法

一段地址被收录，只有两种情况：

1. **有国内路径**：从境外采集点观测到的 AS 路径，从 origin 往上游一路都是中国登记的网络，并且经过电信、联通、移动、教育网或科技网的骨干 ASN（AS4134、AS4809、AS4837、AS9929、AS9808、AS4538、AS23911、AS7497）。骨干直接连着 origin、而地址又登记在境外时不算，这是骨干海外节点的形态。
2. **没有任何宣告，且登记在中国**：境外看不到宣告的地址只可能闲置或只在国内路由。

其余一律排除，包括只经境外网络宣告的中国 ASN 前缀、境外 ASN 宣告的地址、RPKI 验证无效的宣告。更具体的前缀优先。

每次发布前自动检查数据源的新鲜度、骨干 ASN 是否仍在国内路径上，以及条目数下限；任何一项不通过就不发布，保留上一版。

## 数据来源

- 路由快照：[RIPE RIS](https://ris.ripe.net) 与 [RouteViews](https://www.routeviews.org) 的 14 个采集点
- 地址与 ASN 登记：[NRO 合并统计](https://ftp.ripe.net/pub/stats/ripencc/nro-stats/)
- RPKI：[RIPE NCC 每日归档](https://ftp.ripe.net/rpki/)
- AS 名称（仅用于报告）：[RIPE NCC asn.txt](https://ftp.ripe.net/ripe/asnames/asn.txt)

## 许可

代码和数据产物都使用 [MIT](LICENSE) 许可。
