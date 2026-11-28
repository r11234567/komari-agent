# 内存观测的口径

状态：现行。Agent 从各平台采样系统内存，通过统一单位上报。不要用单一 OS 或工具的 used 公式解释所有节点；可回收缓存和 available 的口径由该平台采样实现决定。检查具体实现请看[监控采样](../../monitoring/unit)；老版本与环境的[比较记录](../history/memory-sampling-comparison.md)仅供追溯。
