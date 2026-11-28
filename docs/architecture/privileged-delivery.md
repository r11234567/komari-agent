# Agent 特权配置

状态：现行。服务连接、普通监控策略和受保护的本机特权是独立所有权。面板签名命令绑定目标安装、修订、允许动作及重放保护；同身份操作不得提升 UID 或 Windows 权限。平台身份变更由 Host 或经本机批准的事务处理。恢复不读取任意远程给出的本机配置路径。

实现入口：[本机特权](../../core/privileged) · [运行配置](../../core/runtimeconfig) · [Host](../../internal/hostcmd)。Wire 契约在[协议仓](https://github.com/r11234567/komari-proto/blob/main/docs/contracts/privileged-delivery.md)，操作见[权限说明](../guides/privileges.md)。
