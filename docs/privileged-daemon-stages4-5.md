# 新节点基线与 daemon 配置生效（阶段 4–5）

三消费者统一引用 proto `cb1f5e8abec38b5983b22384e8e234e05de5c531`。Go 依赖固定为 `v0.1.38-0.20261021121746-cb1f5e8abec3`，无本地 replace。

首次连接先协商 protocol 2、service/startup ID、实际 daemon 身份和支持字段。只有服务端显式标记为新节点、没有历史、且本机存在受保护安装策略时，才通过 InitializeNodeConfig 创建 runtime r1 和 privileged r1。immutable bootstrap-request.pb 固定重试内容；重复请求不产生 r2。runtime/privileged 各自在本机持久化并加载后才发 ACK，因此后台短暂显示 applied 0 是等待真实确认，不会用 desired 冒充 applied。旧节点、原 runtime r4、旧 privileged pending r1 均不补造基线。

后续同身份变更沿 v2 sequence 订阅。agent 验完整签名、hash、revision/generation、service/agent、实际身份、动作列表和有效期；应用前再在线核对最新授权，防止尚未过期的旧批准复活。只有 AWAITING_AGENT 且无需 host actions 的变更可在 daemon 内应用。普通账户远控使用该账户的实际权限；这不转换账户，也不获得 root。跨身份与 helper 操作仍明确不支持。

EffectiveConfig 合并 runtime snapshot、active privileged snapshot、已签名 pending 撤权约束、root-owned policy 及实际 daemon 模式。bootstrap --disable-remote-control 不覆盖已应用批准；独立的 protected force-deny 优先。策略缺失、不可读或身份不匹配时拒绝特权能力。config show 输出脱敏磁盘快照、字段来源/阻止原因和回执数量，明确没有实时 daemon 身份证明。

WebSSH 和 execution 分开判权。worker 常驻等待授权，领取与最终执行重新检查；文件命令也在会话入口重查。撤权立即阻止新的相关操作，约 500 ms 内关闭已有受管理任务/PTY/文件会话（本机收到变更以后；Watch 的服务端轮询约 20 秒，面板服务端先挡新调度）。GPU collector 使用有效批准，detailed GPU 同时受 GPU 总开关约束；网卡 IP 选项可以覆盖启动时的 true。runtime 只接受字段 1、3–8、19；其他/未知字段明确拒绝，不推进本机 applied。

daemon 对 runtime 和 privileged 路径持有进程间生命周期锁。privileged 每次落盘额外加写锁并校验磁盘 hash，过期 Store 拒绝覆盖另一写者。CLI 升级/回滚、旧 elevation scripts、rescue 直接 rollback 均退出 daemon 状态写入路径；helper 的受控 daemon 通知留到阶段 6。内部回滚只能缩小权限，不能第二次回滚无认证重开。

普通配置将快照和 immutable ACK 队列同一次原子提交。特权配置将 active signed revision 和 observation/receipt ID 同一次提交；重启后按原 payload/ID 重试，临时网络错误不丢弃。明确的 stale/invalid/precondition 拒绝被归档，不覆盖新状态。privileged rejected receipts 最多保留 128 条，pending 队列最多 1024 条；队列满时拒绝新应用。runtime ACK 使用已有协议的 revision 幂等语义，未增加伪造 receipt 字段。

CI 不在本机运行重测试：

- scripts/ci/run-go-tests.sh：现有 Go 行为回归，JSONL、人类日志、编译 stderr、退出码及失败索引。
- scripts/ci/run-privileged-audit.py：原 6 项缺陷全部提升为强制成功的正式测试，不再期望失败。
- scripts/ci/test-approved-delivery.sh：一次性 GitHub runner 中真实 root-owned policy + 签名 Connect；覆盖接收不批准、篡改、过期当前性、同身份分项入口、force-deny、丢 ACK 和重启原样重试。它验证本机策略文件和传输/daemon 逻辑，不冒充 PAM/真实服务提权验收。
- scripts/ci/test-trusted-install.sh：真实 systemd 元数据的新安装/旧安装迁移；程序/策略不可由 daemon 修改，旧状态文件 hash 不变。
- Windows/macOS/FreeBSD 的 daemon/host 跨编译；新安装及 host 动作只开放 Linux systemd。

每次运行都上传日志 artifact，保留 30 天。生产 FRA、历史任务和运行服务未修改。后续阶段 6 才实现 PAM/系统认证、root 档案转换、helper 安装、完整 host transaction 与故障恢复；当前 komari-host apply 明确报未实现。
