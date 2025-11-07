# Compare Plugin - Silent Mode 快速参考

## 一句话总结
`--silent` 参数让 compare 插件静默执行，不显示进度条和屏幕输出，但保留日志、文件输出和数据库输出。

## 快速使用

### 基本语法
```bash
capmaster compare [其他参数] --silent
```

### 常用组合

#### 1️⃣ 静默 + 文件输出
```bash
capmaster compare \
  --file1 a.pcap --file1-pcapid 0 \
  --file2 b.pcap --file2-pcapid 1 \
  --silent -o result.txt
```

#### 2️⃣ 静默 + 数据库输出
```bash
capmaster compare \
  --file1 a.pcap --file1-pcapid 0 \
  --file2 b.pcap --file2-pcapid 1 \
  --silent --show-flow-hash \
  --db-connection "postgresql://..." --kase-id 133
```

#### 3️⃣ 完全静默（连日志都不显示）
```bash
capmaster --log-level ERROR compare \
  --file1 a.pcap --file1-pcapid 0 \
  --file2 b.pcap --file2-pcapid 1 \
  --silent -o result.txt
```

## 效果对比

| 功能 | 普通模式 | --silent 模式 |
|------|---------|--------------|
| 进度条 | ✅ 显示 | ❌ 不显示 |
| 屏幕输出 | ✅ 显示 | ❌ 不显示 |
| 日志输出 | ✅ 显示 | ✅ 显示 |
| 文件输出 (-o) | ✅ 工作 | ✅ 工作 |
| 数据库输出 | ✅ 工作 | ✅ 工作 |
| 错误提示 | ✅ 显示 | ✅ 显示 |
| 退出码 | ✅ 正常 | ✅ 正常 |

## 适用场景

### ✅ 推荐使用
- 批量处理脚本
- Cron 定时任务
- CI/CD 流程
- 只需要文件/数据库输出

### ❌ 不推荐使用
- 交互式调试
- 首次运行测试
- 需要实时查看结果

## 注意事项

⚠️ `--silent` 只禁用进度条和屏幕输出，不影响日志  
⚠️ 如需控制日志，使用 `--log-level` 参数  
⚠️ 文件输出和数据库输出不受影响  

## 更多信息

详细文档：[SILENT_MODE_GUIDE.md](SILENT_MODE_GUIDE.md)

