# match_tcp_conns.sh - TCP连接级跨捕获点匹配分析工具

## 📖 文档导航

### 主文档（必读）

**[MATCH_TCP_CONNS_GUIDE.md](MATCH_TCP_CONNS_GUIDE.md)** - 完整开发维护指南（唯一官方文档）

这是 `match_tcp_conns.sh` 的**唯一官方开发维护文档**，包含：

- ✅ 快速开始（5分钟上手）
- ✅ 核心功能说明
- ✅ 完整使用方法
- ✅ 工作原理详解
- ✅ 参数详解
- ✅ 使用场景
- ✅ 故障排除
- ✅ 开发维护指南
- ✅ 性能优化
- ✅ 测试指南
- ✅ 版本历史
- ✅ 附录（命令参考、字段映射、证据类型等）

### 快速链接

| 我想... | 查看章节 |
|---------|----------|
| 快速上手 | [快速开始](MATCH_TCP_CONNS_GUIDE.md#快速开始) |
| 了解功能 | [核心功能](MATCH_TCP_CONNS_GUIDE.md#核心功能) |
| 学习使用 | [使用方法](MATCH_TCP_CONNS_GUIDE.md#使用方法) |
| 解决问题 | [故障排除](MATCH_TCP_CONNS_GUIDE.md#故障排除) |
| 优化性能 | [性能优化](MATCH_TCP_CONNS_GUIDE.md#性能优化) |
| 开发修改 | [开发维护](MATCH_TCP_CONNS_GUIDE.md#开发维护) |
| 查看版本 | [版本历史](MATCH_TCP_CONNS_GUIDE.md#版本历史) |
| 快速参考 | [附录A](MATCH_TCP_CONNS_GUIDE.md#a-完整命令参考) |

---

## 🚀 快速开始

### 1. 检查依赖

```bash
# 必需工具
which tshark awk sort xxd md5sum

# tshark版本要求
tshark -v  # >= 4.2
```

### 2. 基本使用

```bash
# 准备输入目录（必须包含2个pcap/pcapng文件）
ls cases/TC-034-3-20210604-S/
# TC-034-3-20210604-S-A-Front-of-F5.pcap
# TC-034-3-20210604-S-B-Back-of-F5.pcap

# 运行匹配
bash match_tcp_conns.sh -i cases/TC-034-3-20210604-S/

# 查看结果
cat cases/TC-034-3-20210604-S/statistics/correlations.txt
```

### 3. 常用命令

```bash
# 查看帮助
bash match_tcp_conns.sh -h

# 自定义输出目录
bash match_tcp_conns.sh -i cases/test/ -o output/

# NAT场景（使用端口分桶）
bash match_tcp_conns.sh -i cases/test/ --bucket port

# Header-only pcap
bash match_tcp_conns.sh -i cases/test/ --mode header

# 大规模场景（强制采样）
bash match_tcp_conns.sh -i cases/large/ --sample 1000

# 降低匹配阈值
bash match_tcp_conns.sh -i cases/test/ --min-score 0.50
```

---

## 📊 核心特性

### v3.0 主要特性

| 特性 | 说明 |
|------|------|
| **目录输入** | 使用 `-i <directory>` 自动扫描2个pcap文件 |
| **智能采样** | 连接数>1000时自动采样，性能提升10倍+ |
| **IPID必要条件** | IPID匹配作为必要条件，降低误匹配率 |
| **自动检测** | 自动检测header-only和最优分桶策略 |
| **NAT友好** | 支持客户端/服务器IP变化场景 |
| **置信度评分** | 多维度指纹匹配，提供置信度分数 |

### 匹配特征（v3.0）

| 特征 | 权重 | 可靠性 |
|------|------|--------|
| **IPID匹配** | 16% | ⭐⭐⭐⭐⭐ |
| SYN选项序列 | 25% | ⭐⭐⭐⭐⭐ |
| 客户端ISN | 12% | ⭐⭐⭐ |
| 服务器ISN | 6% | ⭐⭐⭐ |
| 客户端首包负载 | 15% | ⭐⭐⭐⭐ |
| 服务器首包负载 | 8% | ⭐⭐⭐⭐ |
| TCP时间戳 | 10% | ⭐⭐⭐⭐ |
| 长度形状签名 | 8% | ⭐⭐⭐ |

---

## 📁 文件结构

```
/Users/ricky/Downloads/code/tshark/
├── match_tcp_conns.sh              # 主脚本（1187行）
├── test_match_tcp_conns.sh         # 测试套件
├── MATCH_TCP_CONNS_GUIDE.md        # 唯一官方文档（1434行）✨
├── MATCH_TCP_CONNS_README.md       # 本文档（快速导航）
├── DOCUMENTATION_UPDATE_SUMMARY.md # 文档整合总结
└── cases/                          # 测试用例目录
    ├── TC-001-1-20160407/
    ├── TC-034-3-20210604-S/        # F5负载均衡场景
    ├── TC-034-3-20210604-O/        # 大规模场景（10000+连接）
    └── ...
```

---

## 🔧 使用场景

### 场景1: 防火墙前后

```bash
bash match_tcp_conns.sh -i cases/firewall/
# 自动检测: 服务器IP相同 → server分桶
```

### 场景2: F5/Nginx负载均衡

```bash
bash match_tcp_conns.sh -i cases/f5/
# 自动检测: 服务器IP不同 → port分桶
```

### 场景3: Header-only pcap

```bash
bash match_tcp_conns.sh -i cases/header-only/
# 自动检测: header-only → 不使用负载特征
```

### 场景4: 大规模连接（10000+）

```bash
bash match_tcp_conns.sh -i cases/large/
# 自动检测: 连接数>1000 → 启用采样
# 采样率: 10%, 最多3000个连接
```

---

## 🐛 故障排除

### 常见问题

| 问题 | 解决方案 |
|------|----------|
| 没有找到匹配 | 检查两个pcap是否包含相同流量、时间窗口是否重叠 |
| 置信度很低 | 正常现象（header-only场景），或考虑降低阈值 |
| 误匹配 | 提高阈值 `--min-score 0.70` |
| 性能慢 | 使用采样 `--sample auto` 或预过滤pcap |

详细故障排除请查看 [MATCH_TCP_CONNS_GUIDE.md - 故障排除](MATCH_TCP_CONNS_GUIDE.md#故障排除)

---

## 📈 性能建议

| 连接数 | 建议 |
|--------|------|
| < 100 | `--sample off` |
| 100 - 1000 | 使用默认设置 |
| 1000 - 10000 | `--sample auto` |
| > 10000 | `--sample 1000` |

---

## 🧪 测试

```bash
# 运行测试套件
bash test_match_tcp_conns.sh

# 测试特定场景
bash match_tcp_conns.sh -i cases/TC-001-1-20160407/  # 基本场景
bash match_tcp_conns.sh -i cases/TC-034-3-20210604-S/ # F5负载均衡
bash match_tcp_conns.sh -i cases/TC-034-3-20210604-O/ # 大规模场景
```

---

## 📚 版本历史

### v3.0 (2025-10-30) - 当前版本

- ✅ 目录输入方式
- ✅ 智能采样策略
- ✅ IPID必要条件
- ✅ 性能优化（快速排序）
- ✅ 权重调整

### v2.0 (2025-10-29)

- ✅ 自动分桶策略检测

### v1.x (2025-10-28)

- ✅ 初始版本

详细版本历史请查看 [MATCH_TCP_CONNS_GUIDE.md - 版本历史](MATCH_TCP_CONNS_GUIDE.md#版本历史)

---

## 🤝 贡献

### 报告问题

1. 提供完整的命令行参数
2. 提供输出日志
3. 如可能，提供测试用的pcap文件（脱敏后）

### 提交改进

1. 遵循现有代码风格
2. 添加测试用例
3. 更新 `MATCH_TCP_CONNS_GUIDE.md`
4. 确保向后兼容

---

## 📞 联系方式

**维护者**: Ricky  
**仓库**: `/Users/ricky/Downloads/code/tshark`  
**文档版本**: v3.0  
**最后更新**: 2025-10-30

---

## 📖 相关文档

- **[MATCH_TCP_CONNS_GUIDE.md](MATCH_TCP_CONNS_GUIDE.md)** - 完整开发维护指南（唯一官方文档）
- **[DOCUMENTATION_UPDATE_SUMMARY.md](DOCUMENTATION_UPDATE_SUMMARY.md)** - 文档整合总结
- **[ANALYZE_PCAP_GUIDE.md](ANALYZE_PCAP_GUIDE.md)** - analyze_pcap.sh使用指南

---

**注意**: 本文档仅作为快速导航，完整信息请查看 [MATCH_TCP_CONNS_GUIDE.md](MATCH_TCP_CONNS_GUIDE.md)

