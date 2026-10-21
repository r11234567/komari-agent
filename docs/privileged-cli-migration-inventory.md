# CLI 与配置所有权清单（阶段 3–5 后）

| 入口/字段 | 当前行为 |
| --- | --- |
| endpoint/token、登录凭据、CF Access | 连接 bootstrap；保留，config show 脱敏 |
| service-manifest、config、各 state-file | 共用服务定位；缺安装 manifest 明确要求迁移；多安装显式选服务 |
| interval、memory-include-cache、NIC/mount、month-rotate | 保留 bootstrap，支持的已应用 runtime snapshot 优先 |
| get-ip-addr-from-nic | 已移除 flags OR snapshot，远端 false 可关闭 |
| enable-gpu | 批准后的 privileged snapshot 控制；detailed-gpu 属 runtime，受有效 GPU 总开关限制 |
| disable-remote-control | 原参数作 bootstrap；root-owned policy 的 force-deny 独立优先；旧来源不明必须显式 preserve/release |
| custom-dns、prefer-ip-version、info-report-interval、reconnect-interval、custom-ipv4/6 | 保留本机启动读者；当前不支持 runtime 下发，明确拒绝 ACK |
| disable-auto-update | 兼容本机启动参数；daemon 不替换受保护二进制，host update 用可信 artifact/hash |
| ignore-unsafe-cert | 本机启动字段；当前不支持 runtime 下发，不能通过普通配置放宽传输 |
| max-retries、disable-compression | 无有效 transport 读者；help 标记 Deprecated，兼容解析一个周期 |
| auto-discovery/server-name | 首次注册 bootstrap，保留 |
| show-warning | Windows 专用，保留 |
| config show [--json] | 已实现，脱敏磁盘快照、effective 来源/阻止原因、回执数量；不把 CLI euid 当 daemon 身份 |
| status privileged | 复用 config show 与相同定位 |
| recover show-config | 旧普通磁盘快照查看，兼容保留 |
| upgrade / update-conf | 一个 Cobra 实现和真实 alias；只委托受信 komari-host，host apply 当前明确不可用 |
| rollback / recover rollback-config | 不允许独立 CLI 写 daemon state；需新面板 revision；扩大权限必须新批准 |
| rescue privileged rollback | 旧直接写盘入口关闭，等待阶段 6 受控 daemon 通知 |
| scripts/elevate* | 明确失败，不读密码、不改 JSON、不改服务 |
| 未知 flags | 默认报错，不再静默吞掉拼写/已删除选项 |

旧 tests/privileged-audit/*.txt 保留作审计历史样本，已退出运行路径。原缺陷现有正式行为回归，CI 强制成功。安装/迁移的可信性与 daemon 生效独立验证；host 身份转换、PAM、helper、主机事务恢复仍属阶段 6。
