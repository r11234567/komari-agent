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
升级留下未完成记录时，后续升级和 apply 会停止并指出受保护备份位置，要求
先完成本机恢复。不要把包含凭据的备份目录上传为 CI artifact。

没有 rescue 的节点不会自动安装 rescue。存在 rescue 时不接受仅注册模式的
升级；应移除 `--install-register-only`，让安装器协调两个服务的重启。旧的无
签名 Snapshot、不能读取当前安装或没有协调升级入口的目标版本会被拒绝。

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
sudo launchctl kickstart -k system/com.komari.komari-agent
sudo launchctl print system/com.komari.komari-agent
sudo tail -n 60 /var/log/komari-agent.log
```

`launchctl bootstrap` 成功只表示任务已加载，仍应检查 `state = running` 和日志。安装器会保留参数边界、转义 plist XML，并安装 macOS 的提权脚本。自定义服务名时，对应 label 为 `com.komari.<服务名>`。

## Windows

Windows 安装器目前仅开放普通监控模式：服务固定使用 `LocalService`，强制关闭远程控制、WebSSH、远程执行，不安装救援或提权脚本。无需新版 Agent，使用当前发布的二进制即可；Windows 的特权 v2 初始化、特权配置下发和主机动作仍不受支持。不要用面板的特权配置完成状态判断普通监控是否在线。

在管理员 PowerShell 执行：

```powershell
$script = irm 'https://raw.githubusercontent.com/r11234567/komari-agent/main/install.ps1'
& ([scriptblock]::Create($script)) -e 'https://panel.example.com'
```

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

## 验证修复

`go test ./cmd ./clientcore ./core/credentials` 验证路径选择、显式覆盖、环境变量优先级、注册前的写权限检查和客户端凭据处理。

`python scripts/test_installers.py` 在临时目录中执行安装器的实际参数解析、状态布局和服务定义生成代码，以模拟服务管理器验证 systemd/launchd/NSSM 的启动失败、未注册状态和参数转义，不安装真实服务。真实 Linux/macOS 服务仍需在对应系统部署验证。
