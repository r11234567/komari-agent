# S01 第三轮：代理错误与领域拒绝

本包与 Server 的入口第三轮组合交付；不修改 wire 或 Proto gitlink，协议仍为
`1de1d15f77b3f0aea1160bd6c06976d2a094aaeb`。Web 无消费 API 变化。

凭据主动续期不再把 SDK 从 HTTP 状态合成的 unauthenticated/permission_denied
当作永久吊销。使用 Connect SDK 的 `IsWireError` 保留协议解码边界：

- 代理 HTML 401/403/429/502、网络和解析失败沿用有界重试与缓存预算，保留现有凭据和 durable pending operation。
- 真正解码出的原生 RPC Unauthenticated/PermissionDenied 仍停止主动续期，反应式请求也保留拒绝缓存，不因重试修复而弱化真实吊销。
- bootstrap/refresh 仍不携带 Bearer 或浏览器 Cookie；恢复后只接受已验证签名的响应，并由既有存储原子发布凭据。

Windows Go 1.26 的 enrollment/clientcore 单元回归和 go vet 已通过；新增真实 HTTP
代理错误→同操作恢复→签名验证与持久提交，以及原生双类拒绝测试。Linux race 回归在
原 Credential lifecycle Agent stage CI 执行。最终远程验收结果由 Server 三轮报告登记。
不声称刷新事务状态机 S03 已被本包替换，也不声称真实 Cloudflare 账户已实测。
