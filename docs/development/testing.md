# Agent 验证

先初始化协议子模块，再执行 `go test ./...`。本地构建 Agent、Rescue 和 Host；发布资产额外验证签名、公钥元数据和校验和。[平台矩阵](../../.github/workflows/platform-checks.yml)验证实际系统行为，[安装器 E2E](../../.github/workflows/installer-platform-e2e.yml)验证干净安装和注册，[流量 E2E](../../.github/workflows/traffic-anomaly-e2e.yml)验证 Linux 采集。用覆盖目标的真实系统运行权限、service 和 eBPF 场景；交叉编译只证明编译。

本机特权 fixture 和运行命令见[测试目录](../../tests/privileged-audit/README.md)。[历史记录](../history/README.md)保留阶段断言和验证出处。
