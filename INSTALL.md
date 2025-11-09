# CapMaster 安装指南

## 依赖管理说明

CapMaster 使用版本锁定的依赖管理，确保不同环境的一致性。

### 依赖文件说明

| 文件 | 用途 | 何时使用 |
|------|------|----------|
| `requirements.txt` | 生产环境依赖（锁定版本） | 部署、生产环境 |
| `requirements-dev.txt` | 开发环境依赖（包含测试、格式化、类型检查） | 开发、CI/CD |
| `requirements-database.txt` | 可选数据库依赖（PostgreSQL 支持） | 需要数据库输出功能时 |
| `pyproject.toml` | 项目配置和依赖范围定义 | 包管理、构建 |

---

## 安装方式

### 方式 1: 使用 requirements.txt（推荐用于生产环境）

```bash
# 1. 克隆仓库
git clone https://github.com/yourusername/capmaster.git
cd capmaster

# 2. 创建虚拟环境
python3.10 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. 安装生产依赖
pip install -r requirements.txt

# 4. 安装项目（可编辑模式）
pip install -e .

# 5. 验证安装
capmaster --version
```

### 方式 2: 使用 pip install（推荐用于开发）

```bash
# 1. 克隆仓库
git clone https://github.com/yourusername/capmaster.git
cd capmaster

# 2. 创建虚拟环境
python3.10 -m venv venv
source venv/bin/activate

# 3. 安装开发依赖（包含生产依赖）
pip install -e ".[dev]"

# 4. 验证安装
capmaster --version
pytest --version
black --version
mypy --version
```

### 方式 3: 仅安装核心功能

```bash
# 最小化安装（仅核心依赖）
pip install -r requirements.txt
pip install -e .
```

---

## 可选功能安装

### 数据库支持（PostgreSQL）

如果需要使用 `--db-connection` 参数将结果写入 PostgreSQL 数据库：

```bash
# 方式 1: 使用 requirements 文件
pip install -r requirements-database.txt

# 方式 2: 使用 pip extras
pip install -e ".[database]"

# 方式 3: 直接安装
pip install psycopg2-binary
```

**使用示例**：
```bash
capmaster compare -i /path/to/pcaps/ \
  --show-flow-hash \
  --db-connection "postgresql://user:password@host:port/db" \
  --kase-id 133
```

---

## 开发环境设置

### 完整开发环境

```bash
# 1. 安装所有依赖（开发 + 数据库）
pip install -r requirements-dev.txt
pip install -r requirements-database.txt
pip install -e .

# 2. 验证工具链
pytest --version          # 测试框架
black --version           # 代码格式化
mypy --version            # 类型检查
python -c "import psycopg2; print('Database support: OK')"

# 3. 运行测试
pytest

# 4. 代码格式化
black capmaster/

# 5. 类型检查
mypy capmaster/
```

### Pre-commit 钩子（可选）

```bash
# 安装 pre-commit
pip install pre-commit

# 设置 git hooks
pre-commit install

# 手动运行所有检查
pre-commit run --all-files
```

---

## CI/CD 环境

### GitHub Actions / GitLab CI

```yaml
# .github/workflows/test.yml 示例
- name: Install dependencies
  run: |
    python -m pip install --upgrade pip
    pip install -r requirements-dev.txt
    pip install -e .

- name: Run tests
  run: pytest --cov=capmaster

- name: Type check
  run: mypy capmaster/

- name: Format check
  run: black --check capmaster/
```

---

## 依赖版本说明

### 核心依赖（requirements.txt）

| 包 | 版本范围 | 说明 |
|---|----------|------|
| click | >=8.1.0,<9.0.0 | CLI 框架 |
| rich | >=13.0.0,<15.0.0 | 终端美化、进度条 |
| pyyaml | >=6.0,<7.0 | YAML 配置解析 |

### 开发依赖（requirements-dev.txt）

| 包 | 版本范围 | 说明 |
|---|----------|------|
| pytest | >=7.4.0,<9.0.0 | 测试框架 |
| pytest-cov | >=4.1.0,<7.0.0 | 测试覆盖率 |
| black | >=23.0.0,<26.0.0 | 代码格式化 |
| ruff | >=0.1.0,<1.0.0 | 快速 linter |
| mypy | >=1.5.0,<2.0.0 | 静态类型检查 |
| types-PyYAML | >=6.0.0,<7.0.0 | PyYAML 类型存根 |

### 可选依赖（requirements-database.txt）

| 包 | 版本范围 | 说明 |
|---|----------|------|
| psycopg2-binary | >=2.9.0,<3.0.0 | PostgreSQL 适配器 |

---

## 常见问题

### Q1: 为什么有多个 requirements 文件？

**A**: 分离关注点，提高灵活性：
- 生产环境只需要核心依赖（小体积、快速部署）
- 开发环境需要测试和代码质量工具
- 数据库功能是可选的，不是所有用户都需要

### Q2: 如何更新依赖版本？

**A**: 
```bash
# 1. 更新 pyproject.toml 中的版本范围
# 2. 重新生成 requirements.txt
pip install -e .
pip freeze | grep -E "(click|rich|pyyaml)" > requirements.txt.new

# 3. 手动整理 requirements.txt.new，保留注释
# 4. 测试新版本
pytest

# 5. 提交更新
git add pyproject.toml requirements*.txt
git commit -m "chore: update dependencies"
```

### Q3: psycopg2-binary vs psycopg2？

**A**: 
- `psycopg2-binary`: 预编译二进制包，安装简单，适合开发和测试
- `psycopg2`: 需要编译，适合生产环境（性能更好）

CapMaster 使用 `psycopg2-binary` 以降低安装门槛。

### Q4: 为什么不使用 Poetry 或 Pipenv？

**A**: 
- 项目使用标准的 `pyproject.toml` + `requirements.txt`
- 兼容性好，适合各种 CI/CD 环境
- 简单直接，不引入额外的工具依赖
- 如果需要，可以轻松迁移到 Poetry

---

## 验证安装

### 检查核心功能

```bash
# 1. 版本信息
capmaster --version

# 2. 帮助信息
capmaster --help

# 3. 插件列表
capmaster analyze --help
capmaster match --help
capmaster compare --help
capmaster filter --help
capmaster clean --help

# 4. 依赖检查
python -c "import click, rich, yaml; print('Core dependencies: OK')"
```

### 检查可选功能

```bash
# 数据库支持
python -c "import psycopg2; print('Database support: OK')" || echo "Database support: Not installed"

# 开发工具
pytest --version || echo "pytest: Not installed"
black --version || echo "black: Not installed"
mypy --version || echo "mypy: Not installed"
```

---

## 卸载

```bash
# 卸载 CapMaster
pip uninstall capmaster

# 清理虚拟环境
deactivate
rm -rf venv/

# 清理 Python 缓存
find . -type d -name "__pycache__" -exec rm -rf {} +
find . -type f -name "*.pyc" -delete
```

---

## 技术支持

如果遇到安装问题：

1. 检查 Python 版本：`python --version` (需要 >= 3.10)
2. 检查 tshark 版本：`tshark -v` (需要 >= 4.0)
3. 查看详细错误：`pip install -v -r requirements.txt`
4. 提交 Issue：包含错误信息、Python 版本、操作系统信息

