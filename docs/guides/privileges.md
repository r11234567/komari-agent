# Agent 运行账户与权限

先按[服务安装](service-startup.md)使用专用服务账户。监控不需要打开远程控制。管理员在面板授权并不自动改变系统身份；涉及变更服务身份的操作按本机审批流程执行。

| 功能 | Linux 非 root / Windows 受限服务 | 更高权限或特殊要求 |
| --- | --- | --- |
| 常规系统指标、凭据与心跳 | 默认可用，读数止于账号能访问的资源。 | 仅给必要的目录权限。 |
| 系统 Ping、回程路由 | 普通探测依赖系统提供的方式；Linux 原始 ICMP 回程需要适当的 `CAP_NET_RAW`。 | 优先给单个 service 所需能力；不要为探测放开全部 root 权限。 |
| 远程执行、WebSSH | 默认关闭。受支持的同身份配置经签名启用后，具体能力由运行时按平台、子开关和本机否决决定。它们不会获得超出当前账户的权限。 | root 命令需要 Linux root 服务及单独许可；Windows 的 LocalService 不等于管理员。 |
| 自动流量监测 | 普通 Linux 服务账号不自动启动受管 eBPF 采集。 | 受支持 Linux TCX、root 服务及对应节点授权；见[流量监测](traffic-monitoring.md)。 |
| 临时救援入口 | 不由普通 Agent 自动取得防火墙权限。 | 独立的救援辅助进程、本机设置及授权；见[恢复](recovery.md)。 |

Linux 排查时查看 `systemctl show komari-agent -p User -p AmbientCapabilities -p CapabilityBoundingSet`、实际 PID 的有效身份和 service 日志；Windows 在服务管理器中核对 Log On 身份和安装器 ACL。面板报告的能力如与本机不符，分别核对已保存、已下发、实际生效和上报版本。不要重新启用已退役的 daemon 自更新，使用 [Host 更新](host-updates.md)。
