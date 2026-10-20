# 守护进程启动排查

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
