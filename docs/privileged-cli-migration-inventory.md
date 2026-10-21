# CLI 与配置所有权（阶段 6 验收后的清理）

配置查询统一使用 `komari-agent config show [--json]`。输出脱敏磁盘快照、文件时间、有效值来源、本机保护策略、host applied 摘要、helper 的受验证观察和回执数量；不启动 daemon，不写状态，不读取或输出私钥，不把查询进程身份当成 daemon 身份，也不将离线 pending 当成服务端当前 desired。

| 入口/字段 | 当前行为 |
| --- | --- |
| endpoint/token、登录凭据、CF Access、auto-discovery/server-name | 本机连接/注册配置，保留 |
| service-manifest、config、各 state-file、standalone | 本机服务定位，保留；新安装禁止自行覆盖 installer 管理的路径 |
| interval、memory-include-cache、NIC/mount、month-rotate、get-ip-addr-from-nic、detailed-gpu | 公开 flag、短参数、环境变量及普通 JSON 输入已删除；通过面板 runtime 下发 |
| enable-gpu | 公开 flag、环境变量及普通 JSON 输入已删除；通过批准后的 privileged snapshot 控制 |
| disable-remote-control | 本机独立否决，任何在线快照都不能解除；所有配置来源的 true 取并集，false 不能抵消其他本机来源的 deny |
| custom-dns、prefer-ip-version、info-report-interval、reconnect-interval、custom-ipv4/6、ignore-unsafe-cert | 当前服务端不支持下发，保留本机设置 |
| disable-auto-update | 本机设置；受保护安装由 host 管理二进制更新 |
| show-warning | Windows 本机工具，保留 |
| max-retries、disable-compression | 无实际读者，公开 flags/env/普通 JSON 输入全部删除 |
| upgrade、update-conf、rollback、status privileged、recover show-config、recover rollback-config | 真正删除，既不注册 alias，也不保留 stub；额外位置参数明确报错 |
| login、refresh、reauth、status、logout、trust | 保留；status 只查询注册凭据，reauth 保留 UUID/keypair 续认证；endpoint 只保留根级共享参数 |
| recover version/verify/diagnostics、checkMem、listDisk | 本机版本、校验、诊断、硬件查询，保留；诊断不报告 CLI 自身为 daemon 身份 |

新安装器与 daemon 共用公开本机 flags 注册函数，在获取 host 锁或写服务/目录/权限前拒绝已删除参数。两套 Web 共用的安装命令生成器不再拼接 GPU、详细 GPU、NIC 地址采集等在线选项；它们留在配置下发中。

旧 systemd 参数仅能由管理员迁移工具的私有数据解析器读取。`komari-host migrate` 在替换启动参数前解析旧配置，将其写为 root-owned `0640 root:<service-group>` 的 `SERVICE.migration-bootstrap.json`，生成只带 `--config` 的新 unit，不修改现有凭据、runtime/privileged 快照或回执。迁移预览展示目标路径，不输出配置密钥。受保护 manifest 所引用的迁移配置和固定 host-bootstrap 文件可承载历史字段；普通用户配置不能恢复已删除的在线入口。实际身份转换仍需独立本机认证，不是这项离线兼容解析的权限。

旧 `--disable-remote-control` 来源不明时仍必须显式 `--legacy-disable preserve/release`。管理员只有在本地保护 policy 中释放 deny，并完成新的 host 认证事务后，才能生成相应的新 canonical bootstrap。面板不能自行释放本机 deny。

验证脚本：`scripts/ci/check-stage6-compile.sh`、`scripts/ci/test-cli-surface.sh`、`scripts/ci/test-trusted-install.sh`。完整 CI 同时执行现有签名、PAM、systemd、helper、恢复、丢回执和跨平台编译；失败日志 always 上传并保留 30 天。
