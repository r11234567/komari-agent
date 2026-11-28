# Linux 流量采集设计

状态：现行。Agent 支持 TCX/eBPF 采集和已有配置的 nfpcapd 路径。采集与归因分开；用量只来源于采集器的观察，服务日志补充标签但不能修复缺采。重复或旧桶由接收方幂等处理，本地缓存按本地策略保留。

eBPF 对象嵌入 Agent，两种字节序均需保留。生成入口 [build-traffic-ebpf.sh](../../scripts/ci/build-traffic-ebpf.sh) 默认 clang-18，完整回归包含真实网卡、collector 运行状态和覆盖率。旧内核如何选采集器及版本下限见[手动采集说明](../guides/traffic-monitoring.md#旧内核和原有配置)。
