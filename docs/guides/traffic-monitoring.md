# Linux 流量监测

在面板打开节点的 **配置下发 → 特权配置 → 启用流量异常检测**，保存并确认。Linux Agent 已以 root 运行时，直接应用已签名配置，自动选择默认出口以太网卡、读取本机地址、启动 eBPF 采样并上报。Agent 如果需要切换到 root，先完成面板给出的本机授权步骤。然后在 **流量监测** 选择节点查看状态、每小时流量与异常事件。

自动模式使用内置采集器和默认阈值。两种 IP 协议共用默认出口时会一起采集，出口分离时优先选择 IPv4 路由。Agent 定期重新识别出口和本机地址。自动模式不修改 Xray 或其他服务配置，默认显示网卡流量和未归因流量。它需要内核支持 TCX。关闭开关会停止采集，已有记录按原留存期限过期。

## 手动模式

下文适用于需要自定义网卡、Xray 归因、服务归因或旧内核采集器的部署。已有手动部署切换到自动模式时，先停止手动采集服务并移除 Agent 的 `KOMARI_TRAFFIC_EVIDENCE_INBOX` 覆盖。

`komari-agent traffic-anomaly` 在单个 Linux 节点上常驻采集和分析。正常流量只写小时用量，异常才写对端 IP 快照。结果默认保存在本机。需要在面板查看时，可给节点配置下文的上报目录。

流量取证子命令在 Linux 提供。默认采集器需要支持 TCX 的 Linux 内核（上游从 6.6 开始）。无需 systemd 即可运行采集、Xray 归因和上报。配置 systemd 服务用量归因时，相关服务需要启用 `IPAccounting=yes`。

## 先选对网卡

选实际观测计费用量的外部网卡。填写在这张网卡上看到的本机 IPv4、IPv6，Agent 根据报文首尾地址识别入站和出站。地址双方都无法归到本机时，字节记为方向未确定。选择公网口时避免同时观测容器桥、veth、隧道内层或回环。在 NAT、反代或隧道后，快照中的 IP 是采集点实际看到的对端。

eBPF 采集器把对端地址和字节数聚合在内核映射表中，Go 进程每 30 秒读取封存的切片。选择一张以太网接口；出入站探针观察报文后继续交给现有网络规则处理。字节数按照探针处可见的 IP 报文长度计算，网卡卸载和隧道封装可能影响与运营商账单的对比。无需安装 `nfpcapd` 或 `nfdump`，也无需创建临时流文件目录。

```json
{
  "sampler": "ebpf",
  "interface": "eth0",
  "local_addresses": ["192.0.2.10", "2001:db8::10"],
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
    {"unit": "apt-daily-upgrade.service", "group": "system_update", "public_interface_only": true},
    {"unit": "backup.service", "group": "backup"}
  ]
}
```

先修改示例里的地址、标签和实际存在的服务。没有 Xray 时省略 `xray`。没有受管任务时省略 `services`。列出的 systemd 服务需启用 `IPAccounting=yes`。它统计服务的 IPv4 和 IPv6 套接字，包含回环、容器桥和内网流量。旧配置和未设置 `public_interface_only` 的服务仍显示在小时汇总中。只有明确使用同一计费网卡、流量不会与另一项归因重复的任务才设置 `public_interface_only: true`，此时才从未解释量中扣减。经过本机代理、容器或内网的更新、备份和反代应省略该标志。读不到归因计数、计数异常回退或服务重启时，存在缺口的观测会标为不完整。

用有 `CAP_BPF` 和 `CAP_NET_ADMIN` 的专用采集服务运行以下子命令。`state_dir` 必须归采集账号所有，权限为 `0700`。停止服务时探针和映射表随描述符释放。普通 Komari Agent 保持原有启动方式。

```bash
komari-agent traffic-anomaly --config-file /etc/komari/traffic-anomaly.json
```

命名为 `komari-traffic` 的专用账号准备好后，可用以下方式启动一次试点。把二进制路径改成节点实际安装的位置，并让该账号能读取试点配置和 Xray 的统计片段。

```bash
sudo install -d -m 0700 -o komari-traffic -g komari-traffic /var/lib/komari-traffic
sudo systemd-run --unit=komari-traffic --collect \
  -p User=komari-traffic -p Group=komari-traffic \
  -p 'AmbientCapabilities=CAP_BPF CAP_NET_ADMIN' \
  -p 'CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN' \
  -p NoNewPrivileges=yes -p KillMode=control-group -p LimitCORE=0 \
  -p MemoryMax=128M -p MemorySwapMax=0 \
  /usr/lib/komari/komari-agent/komari-agent traffic-anomaly --config-file /etc/komari/traffic-anomaly.json
```

用 `journalctl -u komari-traffic.service` 看采集器状态。试点结束时执行 `sudo systemctl stop komari-traffic.service`。本机过期清理在采集服务运行时和下次启动时执行。TCX 或 capability 不可用时，服务启动会给出错误。

### 旧内核和原有配置

已有 `scratch_dir` 且没有 `sampler` 的配置继续使用 `nfpcapd`。对缺少 TCX 的节点，可显式选择 `"sampler": "nfpcapd"`。安装发行版的 `nfpcapd` 和 `nfdump`，为采集服务使用 `CAP_NET_RAW`，配置限额不超过 64 MiB 的 `noswap` tmpfs 作为 `scratch_dir`。该目录由采集账号拥有，权限为 `0700`。停止服务后可卸载该临时挂载。

Ubuntu 24.04 的 `nfpcapd 1.7.3` 在 Linux 上使用固定的 256 MiB 锁定环形缓冲，`-B` 只调流缓存。出现 `mmap() failed: Resource temporarily unavailable` 时先检查 `LimitMEMLOCK`。可用 `LimitMEMLOCK=320M` 和 `MemoryMax=384M` 作为该模式的起点。

试点会拒绝 `nfpcapd 1.7.10`。在 Rocky Linux 10 的 EPEL 包上，短 UDP 突发已被内核采集，却在链路空闲后未及时导出流记录。这个版本无法满足保留突发对端证据的要求。RHEL 系的回归使用 Rocky Linux 9 的 EPEL 包。

## 在面板查看

面板与 Agent 都需要支持流量取证协议。先在面板绑定 Agent，再让采集程序开始捕获。现有服务名和账号可用 `systemctl show komari-agent.service -p User -p Group` 查看。

1. 建立一个专用中转目录，属主为采集账号，属组为 Agent 服务可读的专用组。示例假设两个服务的账号分别为 `komari-traffic` 和 `komari`。

   ```bash
   sudo install -d -o komari-traffic -g komari -m 2750 /var/lib/komari-traffic-handoff
   ```

2. 在采集器 JSON 中设置 `"upload_dir": "/var/lib/komari-traffic-handoff"`，再重启采集器。中转目录中的记录权限为 `0640`，仅包括小时汇总和异常快照。
3. 用 `sudo systemctl edit komari-agent.service` 添加以下配置，再执行 `sudo systemctl restart komari-agent.service`。自定义服务名需要替换。

   ```ini
   [Service]
   Environment=KOMARI_TRAFFIC_EVIDENCE_INBOX=/var/lib/komari-traffic-handoff
   ```

4. 在面板打开 **管理 → 流量监测**，选择节点。小时汇总在小时结束或采集器正常退出后上报。异常触发后先上报已捕获的证据，后续采集窗口继续更新同一事件。

中转目录由采集器负责清理。断网后 Agent 会在本机留存期限内重试。当前注册之前开始的记录不会上报。面板异常快照自采集窗口结束起保留 72 小时，小时汇总保留 7 天。移除环境变量并重启 Agent 可关闭上报。

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

StatsService 仅监听本机回环。配置的标签排除管理 API、阻断出口及非待计费服务。采集器复用一条本机 gRPC 连接，按精确名称读取 `GetStats`，请求的 `reset` 值固定为 `false`，本地计算相邻增量。计数回退时重新建立基线。采集器无需在 PATH 中安装 Xray 命令。

用 `public_legs` 表明计费网卡能观测到代理路径的哪一侧：

- `inbound` 表示网卡只观测客户端侧，出口通过另一可见接口或隧道。比较 Xray 两端对应方向的容量，再解释客户端侧看到的公网字节。
- `outbound` 表示网卡只观测目标侧。
- `both` 表示两侧都在该网卡。隧道封装也走同一网卡时，按该接口的实际观测结果选择并核对口径。

## 输出与留存

- `hour-*.json` 包含网卡观察量、服务汇总、未解释量、覆盖状态，小时结束或正常停止时写入，保留七天。服务与网卡的字节口径可能不同，服务计数用于解释及研判。
- `event-*.json` 包含触发原因、观测接口、证据时间段、来源和目的 Top 20、其他字节数和过期时间。发现异常后就可读，后续追加最多 5 分钟，结束后 `complete` 变为 true。事件最多 64 KiB，默认 72 小时过期，最多保留 288 项。
- eBPF 与归因采样用同一启动时钟对齐 30 秒切片，写入小时汇总和新快照时换算 UTC。内核用 LRU 保留最多 16,384 个时间片、方向与对端组合。内核淘汰和用户态裁剪的字节继续计入方向总量和快照的其他项。高基数窗口里的对端字节是保留下来的观测下限。`nfpcapd` 模式的临时文件轮转和长连接活跃超时均为 30 秒，分析器清理已读分片。分析中的对端计数保留最近 15 分钟，正常记录随后覆盖。
- 路径两端匹配使用短窗口聚合。快触发用近两分钟，慢触发用连续的五分钟窗口，持续异常用 30 分钟未解释量。含缺口的快触发和持续异常使用三倍阈值，触发后快照标记为部分证据。慢触发和基线学习只使用完整窗口，重启后重新学习。
- 方向识别仅覆盖配置好的本机地址。采集点之前的丢弃不在可见范围内。特别繁忙时，关注 collector 的日志和实际可见用量，实验性采集结果不参与面板账本。

真实网络回归位于 `scripts/ci/test-traffic-anomaly.py`。它启动实际二进制，在隔离 Linux 网络命名空间中运行 Xray 和流量工具，覆盖分路代理、IPv4/IPv6 入站、持续 TCP 出站和普通流量零取证文件。eBPF 矩阵覆盖原生 Ubuntu 24.04，以及 Debian 13、Rocky Linux 9、无 systemd 的 Alpine 3.22 容器。容器使用 runner 的 Linux 内核。Ubuntu 另跑一项 `nfpcapd` 兼容回归。

内核探针源码位于 `internal/trafficwatch/ebpf/capture.c`。修改后在 Linux 用 `bash scripts/ci/build-traffic-ebpf.sh` 重新生成两种字节序的对象，默认使用 `clang-18`。常规 Go 构建使用嵌入的对象。

eBPF 按 TCX 入/出方向统计所选以太网接口观察到的有效 IPv4/IPv6 字节，去除探针可见的以太网和 VLAN 头。本机地址列表仅用于诊断，不再限制 eBPF 收发总量；列表外计数是总量的子集。nfpcapd 仍使用配置的本机地址作为观测范围。其他网卡、非 IP 报文以及抓包钩子外的流量不在此口径内。

每个 30 秒片封口后更新同一个小时文件，并原样交给现有上传器。重新启动时继续该小时的存档，重叠的片不会重复累计。可用 `KOMARI_TEST_TCX=1 go test ./internal/trafficwatch -run TestAutomaticEBPFPublishesInterfaceTraffic -v` 在有 TCX 和网络命名空间权限的隔离 Linux 环境验证实时输出。

小时服务计数仍用于诊断；全局 Xray 计数和 systemd IPAccounting 无法独立证明逐字节与网卡流量吻合，因此不会被当作图表上已归因的字节。
