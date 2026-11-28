# 守护进程启动排查

## Linux：升级已安装的 rescue

安装器同时检查受保护 policy、rescue 程序、配置和 systemd 服务。已有 rescue
时，会先下载同一版本的 Agent、Host、rescue 和发布者签名，在固定本机公钥下
验证 rescue 的版本、平台和 SHA256，再持有主机操作锁整体替换。缺少签名或
安装状态不一致时，在改动程序前退出，不会仅升级 Agent。

升级不改变节点身份、凭据、权限策略、签名公钥或服务原来的启停状态。启动
健康检查失败时，恢复三件程序及 rescue 配置，再验证原来运行的服务。备份和
升级阶段保留在 `/var/lib/komari-host/SERVICE/upgrade-*`，目录仅 root 可读；
失败日志同时包含 Agent 和 rescue 的 systemd 状态与 journal。断电或强制杀死
升级留下 `prepared`、`replacing` 或 `restore_failed` 记录时，重新运行当前安装器、
指定新版签名发布即可重试。协调器持有同一把主机操作锁，先校验记录绑定的安装、
路径、权限和四份原始备份，再使用已验签的目标版本完成整体升级；不会把半套
已替换的程序当作回滚基线。每次重试原样保留上一份失败记录，成功并通过进程
检查后才写 `completed`。损坏、缺失、跨安装或多份 pending 记录会拒绝自动恢复。
不要把包含凭据的备份目录上传为 CI artifact。

三种 pending 分别处理：面板配置等待批准时，软件升级照常，rescue 保持空闲、
不领取或执行任务，直到收到真正有效的签名批准；软件升级中断按上面流程重试；
主机权限事务 `transaction.json` 未结束时，升级在替换任何程序前停止，输出该
安装的 `komari-host resume/restore` 命令。软件升级不会替代面板 2FA 或本机 PAM。
没有 rescue 的普通升级同样在安装前检查 pending 主机事务。

没有 rescue 的节点不会自动安装 rescue。存在 rescue 时不接受仅注册模式的
升级；应移除 `--install-register-only`，让安装器协调两个服务的重启。旧的无
签名 Snapshot、不能读取当前安装或没有新版事务预检入口的目标版本会被拒绝。

## 前台正常、服务退出

先比较两处路径：`login` 输出的 `Credentials stored at ...`，以及服务参数的 `--credentials-file`。它们必须指向同一个文件，并且运行服务的账号必须能读取、更新它和它的父目录。

例如登录保存到 `/home/alice/.config/komari-agent/credentials.json`，systemd 却读取 `/opt/komari/credentials.json`：这是两套独立的状态。前台进程可以使用前者正常启动，服务仍然缺少身份而退出。`Start request repeated too quickly` 是连续退出触发的 systemd 限流，应查看它前面的 Agent 错误。

```bash
sudo systemctl cat komari-agent
sudo systemctl show komari-agent -p User -p ExecStart
sudo journalctl -u komari-agent -b -n 60 --no-pager
```

不要用 `chmod 644 credentials.json` 解决权限问题；文件包含私钥和令牌。Unix 保持 0600，所有者设为实际服务账号，父目录也需要允许服务账号写入，以便自动续期时原子替换文件。

## Linux：迁移已注册的个人凭据

适用于旧版本默认安装：用户登录已成功，服务使用 `/opt/komari/credentials.json`，但此文件尚不存在。先停止该身份的前台进程，避免同时运行两个会轮换凭据的 Agent。

```bash
sudo systemctl stop komari-agent
service_user=$(systemctl show komari-agent -p User --value)
service_user=${service_user:-root}
source_credentials="$HOME/.config/komari-agent/credentials.json"
target_credentials=/opt/komari/credentials.json

# 有现存服务凭据时先检查其 Agent ID，避免覆盖另一个节点的身份。
if sudo test -e "$target_credentials"; then
    echo "服务凭据已存在，请先检查身份及 journalctl 日志，不自动覆盖。"
else
    sudo install -o "$service_user" -m 600 "$source_credentials" "$target_credentials"
    sudo systemctl reset-failed komari-agent
    sudo systemctl restart komari-agent
    sudo systemctl status komari-agent --no-pager -l
fi
```

已有目标文件且确认为相同身份时，修正其所有者即可：`sudo chown "$service_user" /opt/komari/credentials.json`，再设为 0600。若 Agent 日志仍报错，以日志里的具体原因继续排查。

迁移后，旧版 CLI 要显式指定服务文件，例如：

```bash
sudo -u komari /opt/komari/agent status --credentials-file /opt/komari/credentials.json
```

不要继续用个人目录中的旧副本运行 Agent 或刷新凭据。新版本安装器写入 `service-config.json` 后，安装的二进制会自动选择服务路径；仅升级二进制不会为旧安装自动生成此文件，应更新安装器或继续显式指定路径。

## macOS

默认账号为 `_komari`，默认目录为 `/usr/local/komari`。旧版个人凭据通常在 `~/Library/Application Support/komari-agent/credentials.json`。迁移原则与 Linux 相同：不覆盖另一个身份，使用服务账号拥有的 0600 文件。

```bash
sudo -u _komari /usr/local/komari/agent login --endpoint https://panel.example.com
sudo launchctl bootstrap system /Library/LaunchDaemons/com.komari.komari-agent.plist
sudo launchctl print system/com.komari.komari-agent
sudo tail -n 60 /var/log/komari-agent.log
```

`launchctl bootstrap` 后通过 `launchctl print` 和日志确认 `state = running`。安装器会保留参数边界并转义 plist XML。自定义服务名时，对应 label 为 `com.komari.<服务名>`。

macOS 和其他非 systemd 安装需要 Python 3 和支持 Ed25519 的 OpenSSL 3。若系统自带的是 LibreSSL，请先安装 OpenSSL 3，并确保管理员运行安装器时使用的是该版本。可执行文件和服务配置由 root 持有。服务账号只需写入安装目录下的 `state/`，旧版默认位置的状态文件会复制到该目录。

若 `/usr/local` 由 Homebrew 操作账号持有，可通过 `--install-dir '/Library/Application Support/Komari'` 指定 root 管理的目录。注册和排查时使用该目录里的 `agent`。

## Linux OpenRC

启动 OpenRC 后，以 root 运行同一个签名安装器。默认安装目录为 `/usr/lib/komari/komari-agent`，普通监控以 `komari` 账号运行。首次安装后，按提示注册并启用服务。

```bash
sudo -u komari /usr/lib/komari/komari-agent/agent login --endpoint https://panel.example.com
sudo rc-update add komari-agent default
sudo rc-service komari-agent start
sudo rc-service komari-agent status
```

OpenRC 和 launchd 提供普通监控。面板审批提权、Host 主机事务及独立 rescue 服务需要 Linux systemd。安装器会在创建账号或写入服务前拒绝这两种服务管理器上的特权和救援选项。

## Windows

Windows 安装器提供普通监控模式，服务以 `LocalService` 运行。请先为系统安装 Git for Windows，安装器使用其 OpenSSL 校验发布签名，并使用固定 SHA-256 校验 NSSM 下载包。Agent 和 NSSM 均通过校验后，安装器才会替换现有服务的程序。

Windows 基础 GPU 采集默认开启，可通过普通运行时配置显式关闭；它不需要特权下发，也不改变服务身份。NVIDIA 动态指标使用限时四秒的五字段 `nvidia-smi` CSV 查询，避免完整 XML 中非 UTF-8 内容导致整次采集失败。GPU 型号、显存、利用率和温度使用后端的标准指标名及设备标签上报。

日志首次出现 `GPU metrics accepted by panel: devices=... points=...` 表示面板已确认接收包含 GPU 的完整指标批次，每个客户端实例只记录一次。在装有 NVIDIA 驱动的 Windows 测试机上，可设置 `KOMARI_TEST_NVIDIA_GPU=1` 后运行 `go test -run TestWindowsNVIDIAHardwareMetrics -v ./monitoring`，严格验证真实硬件采集和指标转换。普通 CI 没有显卡时跳过这项硬件测试；CSV 解析及协议回归仍正常运行。

以管理员身份打开 PowerShell，按[安装器下载与校验](#安装器下载与校验)操作。

首次安装没有凭据时，安装器会等待登录，并输出下面的登录、启动命令。重复运行安装命令会保留共享状态及节点身份；`--install-rescue` 和 `--install-runtime-identity root-or-administrator` 会在改动服务前拒绝。

LocalService、LocalSystem 和交互用户的 APPDATA 各不相同。新安装器为 NSSM 显式设置全部四个状态路径，并在可执行文件旁写入相同的 CLI 默认值。使用管理员 PowerShell 注册和启动：

```powershell
& "$env:ProgramFiles\Komari\komari-agent.exe" login --endpoint https://panel.example.com
Restart-Service komari-agent
Get-Service komari-agent
Get-Content "$env:ProgramFiles\Komari\logs\agent-stderr.log" -Tail 60
```

若此前已注册到 `%APPDATA%\komari-agent\credentials.json`，先停止前台 Agent 和服务，确认新目标没有另一个身份，再将原凭据复制到 `%ProgramData%\Komari\credentials.json`。保留安装器设置的目录 ACL，确保 LocalService 具有修改权限，以支持自动续期。不要通过再次注册来替代迁移，否则会创建新的节点身份。

NSSM 服务状态为 Running 并不总能证明 Agent 子进程存活。安装器设置 5 秒重启间隔，并在启动后复查状态；Paused 或启动异常时输出 stderr 日志和服务管理器事件。默认服务目录、状态目录的权限在 LocalSystem 模式下也会设置，以支持后续降权回 LocalService。

## 安装器下载与校验

以下命令固定安装器提交并检查脚本 SHA-256。将面板地址改为自己的 HTTPS 地址。安装器按平台从 GitHub 发布列表选择带签名的稳定版，或当前带签名的 Snapshot。可用 `--install-version` 指定[发布页](https://github.com/r11234567/komari-agent/releases)的确切 tag。Linux systemd 需要同一 tag 内的 Agent 和 Host 签名。

```bash
curl -fsSL 'https://raw.githubusercontent.com/r11234567/komari-agent/84604a6271d2f35620ebf542b5fa59ce9c1600b5/install.sh' -o install.sh &&
printf '%s  %s\n' '4378e1221200eddd6722775957e71a7eb4c34be9eaca8155f9802eb868d7e2a0' install.sh | sha256sum -c - &&
sudo bash ./install.sh -e 'https://panel.example.com'
```

macOS 将 `sha256sum` 换成 `shasum -a 256`。

```powershell
Invoke-WebRequest -UseBasicParsing -ErrorAction Stop -Uri 'https://raw.githubusercontent.com/r11234567/komari-agent/84604a6271d2f35620ebf542b5fa59ce9c1600b5/install.ps1' -OutFile .\install.ps1
if ((Get-FileHash -LiteralPath .\install.ps1 -Algorithm SHA256).Hash -ne 'e4e6426209d264929c36723adc12aeb5cfb57592e2392047ade1f93dcb5ec808') {
    throw 'Installer SHA-256 mismatch'
}
& ([scriptblock]::Create((Get-Content -LiteralPath .\install.ps1 -Raw))) -e 'https://panel.example.com'
```

安装器用固定发行公钥验证 `.release.json`，再核对组件、版本、系统、架构和文件 SHA-256。

## 验证修复

`go test ./cmd ./clientcore ./core/credentials` 验证路径选择、显式覆盖、环境变量优先级、注册前的写权限检查和客户端凭据处理。

`python scripts/test_installers.py` 在临时目录中执行安装器的实际参数解析、状态布局和服务定义生成代码，以模拟服务管理器验证 systemd/launchd/NSSM 的启动失败、未注册状态和参数转义，不安装真实服务。真实 Linux/macOS 服务仍需在对应系统部署验证。
