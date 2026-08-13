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

配置优先级从低到高为：默认值、命令行参数、环境变量、JSON 配置文件。

常用配置项：

表中支持版本表示该参数本身首次在发布 tag 中出现；环境变量和 JSON 配置文件方式从 `1.1.33` 起支持，早于最早 tag 的参数记为 `0.0.9`。

| JSON 字段 | 环境变量 | 命令行参数 | 说明 | 支持版本 |
| --- | --- | --- | --- | --- |
| `endpoint` | `AGENT_ENDPOINT` | `--endpoint`, `-e` | 面板地址 | `0.0.9` |
| `token` | `AGENT_TOKEN` | `--token`, `-t` | agent token | `0.0.9` |
| `interval` | `AGENT_INTERVAL` | `--interval`, `-i` | 数据采集间隔，单位秒 | `0.0.9` |
| `disable_auto_update` | `AGENT_DISABLE_AUTO_UPDATE` | `--disable-auto-update` | 禁用自动更新 | `0.0.9` |
| `disable_web_ssh` | `AGENT_DISABLE_WEB_SSH` | `--disable-web-ssh` | 禁用远程控制 | `0.0.9` |
| `ignore_unsafe_cert` | `AGENT_IGNORE_UNSAFE_CERT` | `--ignore-unsafe-cert`, `-u` | 忽略不安全证书 | `0.0.9` |
| `include_nics` | `AGENT_INCLUDE_NICS` | `--include-nics` | 仅统计指定网卡，逗号分隔 | `0.0.22` |
| `exclude_nics` | `AGENT_EXCLUDE_NICS` | `--exclude-nics` | 排除指定网卡，逗号分隔 | `0.0.22` |
| `include_mountpoints` | `AGENT_INCLUDE_MOUNTPOINTS` | `--include-mountpoint` | 仅统计指定挂载点，分号分隔 | `0.1.0` |
| `month_rotate` | `AGENT_MONTH_ROTATE` | `--month-rotate` | 流量统计每月重置日期，`0` 为禁用 | `0.1.0` |
| `auto_discovery_key` | `AGENT_AUTO_DISCOVERY_KEY` | `--auto-discovery` | 自动发现密钥 | `1.0.40` |
| `server_name` | `AGENT_SERVER_NAME` | `--server-name` | 首次使用自动发现密钥注册时显示的服务器名称；未设置时使用系统主机名 | 未发布 |
| `custom_dns` | `AGENT_CUSTOM_DNS` | `--custom-dns` | 自定义 DNS 服务器 | `1.0.80` |
| `enable_gpu` | `AGENT_ENABLE_GPU` | `--gpu` | 启用详细 GPU 监控 | `1.0.80` |
| `protocol_version` | `AGENT_PROTOCOL_VERSION` | `--protocol-version` | 上报协议版本，默认 `2` | `1.2.10` |
| `disable_compression` | `AGENT_DISABLE_COMPRESSION` | `--disable-compression` | 禁用 v2 传输压缩 | `1.2.10` |
| `prefer_ip_version` | `AGENT_PREFER_IP_VERSION` | `--prefer-ip-version` | 优先使用 IP 版本，可选 `4` 或 `6` | 未发布 |

完整参数可运行：

```bash
./komari-agent --help
```

详见 `cmd/flags/flags.go` 及 `cmd/root.go`

## 服务账号与卸载

Linux 默认创建不可登录的专用 `komari` 服务账号，macOS 默认创建隐藏且不可登录的 `_komari` 服务账号；Windows 默认使用不可交互登录的 `NT SERVICE\\komari-agent` 虚拟服务账号。Docker 镜像固定以容器内的非 root `komari` 用户运行。专用服务账号无法执行需要 root 或管理员权限的远程控制操作；只有显式指定 `--install-runtime-identity root-or-administrator` 才以特权账号运行。

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
