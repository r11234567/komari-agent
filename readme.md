# komari-agent

## 配置方式

agent 参数可以通过命令行参数、环境变量或 JSON 配置文件传入。

最小启动示例：

```bash
./komari-agent --endpoint "https://example.com" --token "your-token"
```

使用环境变量：

```bash
export AGENT_ENDPOINT="https://example.com"
export AGENT_TOKEN="your-token"
./komari-agent
```

使用 JSON 配置文件：

```bash
./komari-agent --config ./config.json
```

`config.json` 示例：

```json
{
  "endpoint": "https://example.com",
  "token": "your-token",
  "interval": 3,
  "disable_auto_update": false,
  "disable_web_ssh": false,
  "ignore_unsafe_cert": false
}
```

配置优先级从低到高为：默认值、命令行参数、环境变量、JSON 配置文件。配置文件会保存安装时边界设置；其中仅七项运行时参数可由兼容的 Komari Server 在线更新。

常用配置项：

表中支持版本表示该参数本身首次在发布 tag 中出现；环境变量和 JSON 配置文件方式从 `1.1.33` 起支持，早于最早 tag 的参数记为 `0.0.9`。

| JSON 字段 | 环境变量 | 命令行参数 | 说明 | 支持版本 |
| --- | --- | --- | --- | --- |
| `endpoint` | `AGENT_ENDPOINT` | `--endpoint`, `-e` | 面板地址 | `0.0.9` |
| `token` | `AGENT_TOKEN` | `--token`, `-t` | agent token | `0.0.9` |
| `interval` | `AGENT_INTERVAL` | `--interval`, `-i` | 数据采集间隔，单位秒 | `0.0.9` |
| `disable_auto_update` | `AGENT_DISABLE_AUTO_UPDATE` | `--disable-auto-update` | 禁用自动更新 | `0.0.9` |
| `disable_web_ssh` | `AGENT_DISABLE_WEB_SSH` | `--disable-web-ssh` | 已弃用的“禁用远程控制”兼容别名；新部署使用 `disable_remote_control` | `0.0.9` |
| `ignore_unsafe_cert` | `AGENT_IGNORE_UNSAFE_CERT` | `--ignore-unsafe-cert`, `-u` | 忽略不安全证书 | `0.0.9` |
| `max_retries` | `AGENT_MAX_RETRIES` | `--max-retries`, `-r` | 旧协议兼容传输的最大连续重试次数 | 当前版本 |
| `reconnect_interval` | `AGENT_RECONNECT_INTERVAL` | `--reconnect-interval`, `-c` | Connect 流与兼容传输重连间隔，单位秒 | 当前版本 |
| `info_report_interval` | `AGENT_INFO_REPORT_INTERVAL` | `--info-report-interval` | 类型化系统身份/硬件报告周期，单位分钟 | 当前版本 |
| `include_nics` | `AGENT_INCLUDE_NICS` | `--include-nics` | 仅统计指定网卡，逗号分隔 | `0.0.22` |
| `exclude_nics` | `AGENT_EXCLUDE_NICS` | `--exclude-nics` | 排除指定网卡，逗号分隔 | `0.0.22` |
| `include_mountpoints` | `AGENT_INCLUDE_MOUNTPOINTS` | `--include-mountpoint` | 仅统计指定挂载点，分号分隔 | `0.1.0` |
| `month_rotate` | `AGENT_MONTH_ROTATE` | `--month-rotate` | 流量统计每月重置日期，`0` 为禁用 | `0.1.0` |
| `memory_include_cache` | `AGENT_MEMORY_INCLUDE_CACHE` | `--memory-include-cache` | 内存使用量包含缓存和缓冲区 | 当前版本 |
| `memory_report_raw_used` | `AGENT_MEMORY_REPORT_RAW_USED` | `--memory-exclude-bcf` | 使用排除 buffer/cache/free 的原始内存口径 | 当前版本 |
| `auto_discovery_key` | `AGENT_AUTO_DISCOVERY_KEY` | `--auto-discovery` | 自动发现密钥 | `1.0.40` |
| `server_name` | `AGENT_SERVER_NAME` | `--server-name` | 首次使用自动发现密钥注册时显示的服务器名称；未设置时使用系统主机名 | 未发布 |
| `custom_dns` | `AGENT_CUSTOM_DNS` | `--custom-dns` | 自定义 DNS 服务器 | `1.0.80` |
| `enable_gpu` | `AGENT_ENABLE_GPU` | `--enable-gpu` | 启用 GPU 采集；详细指标另用 `detailed_gpu` | `1.0.80` |
| `protocol_version` | `AGENT_PROTOCOL_VERSION` | `--protocol-version` | 上报协议版本，默认 `2` | `1.2.10` |
| `disable_compression` | `AGENT_DISABLE_COMPRESSION` | `--disable-compression` | 禁用 v2 传输压缩 | `1.2.10` |
| `prefer_ip_version` | `AGENT_PREFER_IP_VERSION` | `--prefer-ip-version` | 优先使用 IP 版本，可选 `4` 或 `6` | 未发布 |
| `disable_remote_control` | `AGENT_DISABLE_REMOTE_CONTROL` | `--disable-remote-control` | 禁用终端、文件管理与远程命令 | 当前版本 |
| `detailed_gpu` | `AGENT_DETAILED_GPU` | `--detailed-gpu` | 启用详细 GPU 指标 | 当前版本 |
| `custom_ipv4` | `AGENT_CUSTOM_IPV4` | `--custom-ipv4` | 自定义上报 IPv4 地址 | 当前版本 |
| `custom_ipv6` | `AGENT_CUSTOM_IPV6` | `--custom-ipv6` | 自定义上报 IPv6 地址 | 当前版本 |
| `get_ip_addr_from_nic` | `AGENT_GET_IP_ADDR_FROM_NIC` | `--get-ip-addr-from-nic` | 从网卡获取上报 IP 地址 | 当前版本 |
| `cf_access_client_id` | `AGENT_CF_ACCESS_CLIENT_ID` | `--cf-access-client-id` | Cloudflare Access Service Token Client ID，必须与 Secret 一起配置 | 当前版本 |
| `cf_access_client_secret` | `AGENT_CF_ACCESS_CLIENT_SECRET` | `--cf-access-client-secret` | Cloudflare Access Service Token Client Secret | 当前版本 |

完整参数可运行：

```bash
./komari-agent --help
```

详见 `cmd/flags/flag.go` 及 `cmd/root.go`

## Connect-RPC 主链

支持 `Connect-RPC/Protobuf` 的 Komari Server 会作为主通信链路使用以下独立服务：类型化系统报告、指标上报、在线配置、Ping/回程探测、远程命令、远程终端/文件管理、救援操作和 Agent 生命周期事件。指标使用独立 bidi stream，Server 对每个带序号批次逐批 ACK，Agent 只在收到 ACK 后推进序号，流中断时重发尚未确认的批次；系统身份、硬件信息和 capability 则按 `info_report_interval` 通过独立的 unary report 周期更新。

终端在 Agent 侧使用独立 bidi attach；浏览器使用创建会话、带序号 unary 命令和可续传的 server-stream 输出，因此无需将 Agent transport 暴露给 UI。浏览器和 Agent 的观察/租约流到达有界 deadline 后会携带游标重新连接，业务会话、执行状态和 PTY 生命周期不由单次 HTTP 流决定。

远程命令具有不可变命令规格、最大输出、超时、租约、序列 ACK、重连重放和取消终态。远程终端与文件操作受 `remote_control_enabled` 双重限制；文件操作会拒绝符号链接、文件系统根目录、特殊文件、复制到自身和未经校验的上传。Cloudflare Access Service Token 会附加到普通 Agent、自动发现和救援 helper 的 Connect 请求；凭据只留在节点配置和 root-only helper 环境文件中，不上传到 Komari Server。

仅当初始 Connect 配置或报告调用确认 endpoint 不可达，或服务端明确不支持 Connect 时，Agent 才进入旧 v1/v2 兼容传输；鉴权、权限、参数、取消或业务错误不会触发回退。单个可选 Connect service 不受旧 Server 支持时只停用该项能力，不会把新功能绕回旧协议。旧协议不承载新的 Connect 功能。

## 在线配置

以下七项可以由兼容 Server 在线下发并由 Agent 回执实际应用结果，无需重启：

- `memory_include_cache`
- `detailed_gpu`
- `include_nics`
- `exclude_nics`
- `include_mountpoints`
- `interval`
- `month_rotate`

运行时配置会校验采集间隔为 1 至 3600 秒、流量重置日为 0 或 1 至 31；新 revision 优先，离线期间的旧 revision 不会覆盖最新配置。`disable_remote_control`、证书策略、自动更新、上报 IP 来源、安装目录、服务名和 GitHub 代理属于安装/安全边界，变更需要重新安装。

## 服务账号与卸载

Linux 默认创建不可登录的专用 `komari` 服务账号，macOS 默认创建隐藏且不可登录的 `_komari` 服务账号；Windows 默认使用不可交互登录的 `NT AUTHORITY\\LocalService` 受限服务账号。Docker 镜像固定以容器内的非 root `komari` 用户运行。专用服务账号无法执行需要 root 或管理员权限的远程控制操作；只有显式指定 `--install-runtime-identity root-or-administrator` 才以特权账号运行。

Linux systemd 安装仅向普通 Agent 服务授予回程线路 ICMP 探测所需的 `CAP_NET_RAW`，不会授予 root 权限。Docker 仍以非 root 用户运行，启用回程线路监测时需添加 `--cap-add NET_RAW`；未提供该能力时，Agent 会向主控回报明确的探测错误，不影响指标上报和在线状态。

Linux/macOS 卸载：

```bash
curl -fsSL 'https://raw.githubusercontent.com/r11234567/komari-agent/main/install.sh' | sudo bash -s -- --uninstall
```

Windows（管理员 PowerShell）卸载：

```powershell
$script = irm 'https://raw.githubusercontent.com/r11234567/komari-agent/main/install.ps1'
& ([scriptblock]::Create($script)) '--uninstall'
```

Docker 卸载只需删除对应容器、数据卷和按需删除镜像：

```bash
docker rm -f komari-agent
docker volume rm komari-agent-data
docker image rm ghcr.io/r11234567/komari-agent:latest
```
