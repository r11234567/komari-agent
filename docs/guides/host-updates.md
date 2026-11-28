# Agent Host 管理与更新

Agent daemon 不自更新。用本机 `komari-host` 的签名更新流程，按[发布流程](../development/release.md)选发布版本和签名清单。先通过 `komari-host --help` 核对版本支持的命令，确认安装、账户、凭据路径及权限，再在维护窗口操作。旧的 `--disable-auto-update` 只为既有配置兼容，不能启用已经移除的功能。

更新失败时保留事务状态和日志，先用 Host 的状态与恢复入口辨别执行阶段，按[恢复说明](recovery.md)处理。不要用缺少签名附件的二进制覆盖 Host 或删除已有设备凭据。

[各开发阶段的历史细节](../history/README.md)。
