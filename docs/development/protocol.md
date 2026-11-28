# Agent 协议依赖

契约、兼容矩阵和生成入口由[协议仓](https://github.com/r11234567/komari-proto/blob/main/docs/README.md)维护。Agent 固定 `third_party/komari-proto` gitlink；构建前初始化递归子模块，用 `node scripts/ci/check-protocol.cjs --resolve-go` 验证模块解析。更新后测试凭据、Host、救援和流量；面板涉及三方验证时，将 Agent 流量 E2E 的固定提交与面板、Web 的协议 pin 一起校验。
