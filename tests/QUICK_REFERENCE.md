# Test Suite Quick Reference

## 快速开始

```bash
# 运行所有测试
pytest

# 快速测试（仅单元测试）
pytest -m "not integration"

# 完整测试（包括集成测试）
pytest -m integration

# 带覆盖率
pytest --cov=capmaster
```

## 常用命令

### 按类型运行

```bash
# 单元测试（快速，~79个测试）
pytest -m "not integration" -v

# 集成测试（较慢，~204个测试）
pytest -m integration -v

# 所有测试（283个测试）
pytest -v
```

### 按组件运行

```bash
# 核心功能
pytest tests/test_core/ -v

# Analyze 插件
pytest tests/test_plugins/test_analyze/ -v

# Match 插件
pytest tests/test_plugins/test_match/ -v

# Compare 插件
pytest tests/test_plugins/test_compare/ -v

# Preprocess 插件
pytest tests/test_plugins/test_preprocess/ -v

# Clean 插件
pytest tests/test_plugins/test_clean.py -v
```

### 按文件/类/方法运行

```bash
# 运行特定文件
pytest tests/test_core/test_file_scanner.py -v

# 运行特定类
pytest tests/test_core/test_file_scanner.py::TestPcapScanner -v

# 运行特定方法
pytest tests/test_core/test_file_scanner.py::TestPcapScanner::test_scan_single_file -v
```

### 按模式运行

```bash
# 运行名称匹配的测试
pytest -k "test_scan" -v

# 排除某些测试
pytest -k "not slow" -v

# 多个模式
pytest -k "test_scan or test_parse" -v
```

## 覆盖率报告

```bash
# 终端输出
pytest --cov=capmaster --cov-report=term

# HTML 报告
pytest --cov=capmaster --cov-report=html
open htmlcov/index.html

# 缺失行报告
pytest --cov=capmaster --cov-report=term-missing
```

## 调试

```bash
# 显示打印输出
pytest -s

# 详细输出
pytest -v

# 超详细输出
pytest -vv

# 在第一个失败处停止
pytest -x

# 在N个失败后停止
pytest --maxfail=3

# 显示完整的 traceback
pytest --tb=long

# 显示简短的 traceback
pytest --tb=short

# 不显示 traceback
pytest --tb=no

# 进入 pdb 调试器
pytest --pdb
```

## 性能

```bash
# 显示最慢的10个测试
pytest --durations=10

# 显示所有测试的耗时
pytest --durations=0

# 并行运行（需要 pytest-xdist）
pytest -n auto
```

## 测试选择

```bash
# 只运行上次失败的测试
pytest --lf

# 先运行上次失败的，再运行其他
pytest --ff

# 运行新添加的测试
pytest --nf
```

## CI/CD 常用命令

```bash
# 快速反馈（单元测试 + 覆盖率）
pytest -m "not integration" --cov=capmaster --cov-report=term

# 完整验证（所有测试）
pytest --cov=capmaster --cov-report=xml

# 严格模式（警告视为错误）
pytest --strict-warnings
```

## 测试统计

```
总计: 283 个测试
├── 单元测试: 79 个 (28%)
└── 集成测试: 204 个 (72%)

按组件:
├── Core: 23 个
├── Analyze: 120 个

├── Match: 25 个
├── Compare: 30 个
├── Clean: 20 个
└── Flow Hash: 20 个
```

## 外部依赖

### 必需
- Python 3.10+
- tshark 4.0+

### 可选
- PCAP 测试文件（`cases/` 目录）
  - 如果缺失，相关测试会自动跳过

## 常见问题

### 测试收集错误
```bash
# 确保 Python 版本正确
python --version  # 应该是 3.10+

# 确保安装了开发依赖
pip install -e ".[dev]"
```

### tshark 未找到
```bash
# macOS
brew install wireshark

# Ubuntu/Debian
sudo apt-get install tshark

# 验证
tshark --version
```

### PCAP 文件未找到
```
这是正常的！相关测试会自动跳过。
如果需要运行这些测试，请准备测试数据。
```

## 更多信息

- 完整文档: `tests/README.md`
- 过时测试说明: `tests/legacy/` 目录下的测试不会参与默认收集，可用于临时或历史用例。

