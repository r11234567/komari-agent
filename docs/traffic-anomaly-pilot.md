# Linux 流量异常取证试点

`komari-agent traffic-anomaly` 在单个 Linux 节点上常驻采集和分析。正常流量只写小时用量，异常才写对端 IP 快照。试点的结果保存在本机，便于用真实节点验证采集口径、误报和资源开销。

## 先选对网卡

选实际观测计费用量的外部网卡。填写在这张网卡上看到的本机 IPv4、IPv6，Agent 根据报文首尾地址识别入站和出站。地址双方都无法归到本机时，字节记为方向未确定。选择公网口时避免同时观测容器桥、veth、隧道内层或回环。在 NAT、反代或隧道后，快照中的 IP 是采集点实际看到的对端。

准备包含 `nfpcapd` 和 `nfdump` 的发行版包。初版在 Ubuntu 24.04 的 1.7.3 上跑回归。给收集器单独的服务账号、抓取该网卡所需的能力、两个私有目录，并给进程组设 CPU 和内存预算。临时目录必须是单独挂载、有 `noswap`、容量不超过 64 MiB 的 tmpfs。两个目录权限为 0700，由收集器账号拥有。

```json
{
  "interface": "eth0",
  "local_addresses": ["192.0.2.10", "2001:db8::10"],
  "scratch_dir": "/run/komari-traffic",
  "state_dir": "/var/lib/komari-traffic",
  "thresholds": {
    "fast_bytes": 300000000,
    "slow_bytes": 1000000000,
    "sustained_bytes": 1500000000
  },
  "xray": {
    "endpoint": "127.0.0.1:10085",
    "policy_file": "/etc/xray/conf.d/15-komari-stats.json",
    "inbound_tags": ["proxy-client"],
    "outbound_tags": ["proxy-upstream"],
    "public_legs": "inbound"
  },
  "services": [
    {"unit": "apt-daily-upgrade.service", "group": "system_update"},
    {"unit": "backup.service", "group": "backup"}
  ]
}
```

先修改示例里的地址、标签和实际存在的服务。没有 Xray 时省略 `xray`。没有受管任务时省略 `services`。列出的 systemd 服务需启用 `IPAccounting=yes`。任务无法采样、服务计数归零或统计 API 不可用时，对应观测窗口标为归因不完整。

用专用账号运行以下子命令，或把它放进单独的 systemd 单元。给采集器所在单元配置抓网卡所需的 capability，给临时挂载指定该账号的 UID/GID，并使用 `KillMode=control-group` 一起回收采集子进程。普通 Komari Agent 保持原有启动方式。

```bash
komari-agent traffic-anomaly --config-file /etc/komari/traffic-anomaly.json
```

命名为 `komari-traffic` 的专用账号准备好后，可用以下方式启动一次试点。把二进制路径改成节点实际安装的位置，并让该账号能读取试点配置和 Xray 的统计片段。

```bash
sudo install -d -m 0700 -o komari-traffic -g komari-traffic /run/komari-traffic /var/lib/komari-traffic
sudo mount -t tmpfs -o "noswap,size=32M,mode=0700,uid=$(id -u komari-traffic),gid=$(id -g komari-traffic)" tmpfs /run/komari-traffic
sudo systemd-run --unit=komari-traffic --collect \
  -p User=komari-traffic -p Group=komari-traffic \
  -p AmbientCapabilities=CAP_NET_RAW -p CapabilityBoundingSet=CAP_NET_RAW \
  -p NoNewPrivileges=yes -p KillMode=control-group -p LimitCORE=0 \
  -p MemoryMax=128M -p MemorySwapMax=0 \
  /usr/lib/komari/komari-agent/komari-agent traffic-anomaly --config-file /etc/komari/traffic-anomaly.json
```

用 `journalctl -u komari-traffic.service` 看采集器状态。试点结束时先执行 `sudo systemctl stop komari-traffic.service`，再卸载该临时挂载。本机过期清理在采集服务运行时和下次启动时执行。

## Xray 和分路

让运行中的 Xray 加载下述聚合配置，且其他配置文件里的 `policy.levels` 不开启 `statsUser*`。分析器用该配置片段检查聚合统计开关，再对显式配置的标签逐个读取聚合计数。

```json
{
  "stats": {},
  "policy": {
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  }
}
```

StatsService 仅监听本机回环。配置的标签排除管理 API、阻断出口及非待计费服务。集成器用精确名称读取 `GetStats`，每次显式设置 `reset=false`，本地计算相邻增量。读取前后任何计数回退，重新建立基线。

用 `public_legs` 表明计费网卡能观测到代理路径的哪一侧：

- `inbound` 表示网卡只观测客户端侧，出口通过另一可见接口或隧道。比较 Xray 两端对应方向的容量，再解释客户端侧看到的公网字节。
- `outbound` 表示网卡只观测目标侧。
- `both` 表示两侧都在该网卡。隧道封装也走同一网卡时，按该接口的实际观测结果选择并核对口径。

## 输出与留存

- `hour-*.json` 包含网卡观察量、服务汇总、未解释量、覆盖状态，小时结束或正常停止时写入，保留七天。服务与网卡的字节口径可能不同，服务计数用于解释及研判。
- `event-*.json` 包含触发原因、观测接口、证据时间段、来源和目的 Top 20、其他字节数和过期时间。发现异常后就可读，后续追加最多 5 分钟，结束后 `complete` 变为 true。事件最多 64 KiB，默认 72 小时过期，最多保留 288 项。
- 临时文件按 30 秒轮转，长连接活跃超时也为 30 秒。分析器读取并清理分片，分析中的对端计数保留最近 15 分钟。正常记录随后覆盖。
- 路径两端匹配使用短窗口聚合。快触发用近两分钟，慢触发用连续的五分钟窗口，持续异常用 30 分钟未解释量。基线从观测完整的窗口逐步建立，重启后重新学习。
- 方向识别仅覆盖配置好的本机地址。采集点之前的丢弃不在可见范围内。特别繁忙时，关注 collector 的日志和实际可见用量，实验性采集结果不参与面板账本。

真实网络回归位于 `scripts/ci/test-traffic-anomaly.py`。它启动实际二进制，在隔离 Linux 网络命名空间中运行 Xray 和流量工具，覆盖分路代理、IPv4/IPv6 入站、持续 TCP 出站和临时文件清理。
