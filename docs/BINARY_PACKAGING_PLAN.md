# CapMaster macOS Binary Packaging Plan

> 目标：在当前 macOS 环境下，将 `capmaster` CLI 打包为可在任意目录运行的单文件二进制，并确保后续代码更新后可沿用同一流程产出新版本。

---

## 1. 适用范围与目标
- **运行环境**：macOS 13+（Apple Silicon & Intel）。
- **CLI 入口**：`capmaster.cli:main`（在 `pyproject.toml` 中的 `console_scripts` 已指向此入口）。
- **输出物**：经 `pyinstaller` 构建的单一可执行文件，连同所需资源归档为 `artifacts/capmaster-macos-<arch>-v<version>.tar.gz`。
- **依赖约束**：不修改 runtime 依赖，仅在构建虚拟环境内安装 `pyinstaller` 及其脚本所需工具。

---

## 2. 构建环境准备
1. **创建 / 激活虚拟环境**（建议 Python 3.12，以与正式包一致）
   ```bash
   python3.12 -m venv .venv
   source .venv/bin/activate
   python -m pip install --upgrade pip
   ```
2. **安装依赖**
   ```bash
   pip install -r requirements.txt -r requirements-dev.txt
   pip install "pyinstaller==6.*"
   ```
3. **外部依赖**：构建产物仍依赖系统已安装的 `tshark`。构建脚本需检查 `command -v tshark` 并在缺失时提示。

---

## 3. 文件布局
```
packaging/
  capmaster-mac.spec          # PyInstaller spec（纳入版本库）
  hooks/
    hook-capmaster.plugins.py
    hook-capmaster.plugins.analyze.modules.py
scripts/
  build_binary.sh             # 主构建脚本
  tests/run_binary_smoke.sh   # 打包后冒烟验证
artifacts/                    # 构建输出（git 忽略）
```

---

## 4. PyInstaller Spec 设计
> 位置：`packaging/capmaster-mac.spec`

关键点：
- **入口**：`Analysis(['capmaster/cli.py'], pathex=['.'], ...)`， `console=True`，`name='capmaster'`。
- **动态插件**：使用 `collect_submodules` 自动收集 `capmaster.plugins` 及 `capmaster.plugins.analyze.modules`，避免手动列表遗漏。
- **资源文件**：
  - 复制 `capmaster/resources/**`（运行期默认模板）。
  - 复制仓库根部的 `resources/services.txt`、`resources/*.yaml` 等示例资源，保持文档示例仍可运行。
- **输出路径**：在 spec 顶部使用 `Path.cwd()` 推导仓库根目录，并设置
   `distpath="dist"`、`workpath="build/capmaster-mac"`，避免 PyInstaller 将单文件结果放入临时目录。
- **可执行体**：`EXE(..., exclude_binaries=False)`，否则单文件模式会缺失 Python shared library；不要再引入 `COLLECT`，保持单文件输出。
- **Hook 搜索路径**：`hookspath=["packaging/hooks"]`，无需在 CLI 再指定 `--additional-hooks-dir`。
- **版本信息**：从 `capmaster.cli.__version__` 读取，在构建脚本中调用 `python -m capmaster --version` 并保存结果，用于产物命名。

示例片段（可直接放入 spec 文件上方的 Python 区域）：
```python
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

plugin_modules = collect_submodules("capmaster.plugins")
analyze_modules = collect_submodules("capmaster.plugins.analyze.modules")

data_capmaster = collect_data_files("capmaster", includes=["resources/*"])
data_root_resources = collect_data_files(
    "resources",
    includes=["*.txt", "*.yaml", "*.yml"],
    excludes=["sample_captures/*", "cases/*"]
)
```
在 `EXE` 段落中合并：
```python
exe = EXE(
    pyz,
    a.scripts,
    ...,
    exclude_binaries=False,
    name="capmaster",
    console=True,
)
```
并在 `COLLECT` 中加入：
```python
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas + data_capmaster + data_root_resources,
    strip=False,
    upx=False,
)
```

---

## 5. PyInstaller Hooks
> 目录：`packaging/hooks/`

1. **`hook-capmaster.plugins.py`**
   - 目的：确保 `capmaster.plugins` 下所有子包（`match`, `compare`, `preprocess`, `topology`, `streamdiff`, `pipeline`, 以及未来新增）被收集。
   - 内容：
     ```python
     from PyInstaller.utils.hooks import collect_submodules

     hiddenimports = collect_submodules("capmaster.plugins")
     ```

2. **`hook-capmaster.plugins.analyze.modules.py`**
   - 目的：`capmaster.plugins.analyze.modules.discover_modules()` 在运行时按字符串导入 20+ 子模块；须显式告知 PyInstaller。
   - 内容：
     ```python
     from PyInstaller.utils.hooks import collect_submodules

     hiddenimports = collect_submodules("capmaster.plugins.analyze.modules")
     ```

> 若未来新增其他依赖动态导入的包（如 `capmaster.something.loader`），在 hooks 目录新增相应钩子即可。

---

## 6. 构建脚本 `scripts/build_binary.sh`

职责：串联整个构建流程并输出 tarball。建议内容：
1. `set -euo pipefail`，确认当前已激活 `.venv`。
2. 检查 `pyinstaller` 和 `tshark` 可用。
3. 读取版本号：
   ```bash
   VERSION=$(python -m capmaster --version 2>/dev/null | awk '{print $NF}')
   : "${VERSION:=$(python scripts/show_version.py)}"  # 备用方案
   ```
4. 清理旧产物：`rm -rf build dist artifacts/capmaster-*`。
5. 调用 PyInstaller：
   ```bash
   pyinstaller --clean --noconfirm packaging/capmaster-mac.spec
   ```
6. 对 `dist/capmaster` 进行 ad-hoc 签名：
   ```bash
   codesign --force --timestamp --sign - dist/capmaster
   ```
7. 归档：
   ```bash
   mkdir -p artifacts
   OUT=artifacts/capmaster-macos-$(uname -m)-v${VERSION}
   cp dist/capmaster "$OUT"
   tar -C artifacts -czf ${OUT}.tar.gz $(basename "$OUT")
   ```
8. 输出校验信息（`shasum -a 256 ${OUT}.tar.gz`）。

附加说明：
- 构建脚本会在启动时确认 `.venv` 已激活并检测 `pyinstaller` 与 `tshark` 是否可用；若缺失会以明确错误退出。
- 使用 `codesign --force` 便于在本地多次构建时覆盖 PyInstaller 写入的临时签名。
- 脚本会保留 `dist/capmaster` 以便本地调试，同时把同一可执行文件复制到 `artifacts/capmaster-macos-<arch>-v<version>` 并打包归档。

---

## 7. 冒烟测试脚本 `scripts/tests/run_binary_smoke.sh`

内容示例：
```bash
#!/usr/bin/env bash
set -euo pipefail
BINARY=${1:-dist/capmaster}
$BINARY --help >/dev/null
$BINARY match --help >/dev/null
$BINARY analyze -i data/2hops/sample.pcap --allow-no-input >/dev/null || true
```
- 可在 CI 中使用示例 PCAP 或空输入，以验证 CLI 能正常启动并加载插件。
- 若需要对 `tshark` 进行更深层验证，可在脚本中提前检查其版本并在缺失时 `skip`。
- 支持设置 `SMOKE_PCAP=/path/to/sample.pcap` 来强制指定输入文件，若未设置则默认以 `--allow-no-input` 做最小化启动验证。

---

## 8. 发布与验证流程
1. `./scripts/build_binary.sh`
2. `./scripts/tests/run_binary_smoke.sh dist/capmaster`
3. 手动运行关键命令（例如 `dist/capmaster match -h`、`dist/capmaster preprocess -i examples/...`）。
4. 将 `artifacts/*.tar.gz` 上传至发布渠道（GitHub Releases、内网制品库等）。
5. 在 Release Note 中注明：
   - 需要用户本地已安装 `tshark`。
   - 默认资源路径（`resources/services.txt`、`capmaster/resources/...`）已包含在包内。

---

## 9. 维护指引
- **新增插件/模块**：只需在源代码中实现并注册，PyInstaller 通过 `collect_submodules("capmaster.plugins")` 自动收集；若新模块依赖额外数据文件，记得更新 spec 中的 `collect_data_files`。
- **资源变化**：新增 YAML/TXT 时，确保命中 `includes` 通配符；若引入大体积样例（如 `data/cases`），评估是否有必要随发行版发布。
- **多架构支持**：在 x86_64 与 arm64 机器上分别运行相同脚本，即可得到对应 tarball；命名中加入架构字段避免混淆。
- **版本迭代**：`build_binary.sh` 永远从源代码读取版本，不需要手动修改脚本；确保在发布前更新 `pyproject.toml` 与 `capmaster/cli.py` 中的版本号。
- **CI 集成**：在 macOS runner 上执行 `build_binary.sh` + `run_binary_smoke.sh`，将 tarball 作为 artifact 上传。后续可扩展为自动推送 release。

---

## 10. 实施检查清单
- [ ] `packaging/capmaster-mac.spec` 已创建且包含 `collect_submodules`/`collect_data_files` 配置，并可在本地无错误加载。
- [ ] `packaging/hooks/hook-capmaster.plugins.py` 与 `packaging/hooks/hook-capmaster.plugins.analyze.modules.py` 落地，运行 `pyinstaller --clean --additional-hooks-dir packaging/hooks` 能看到隐藏导入被识别。
- [ ] `scripts/build_binary.sh` 执行成功，自动读取版本、检查 `tshark`、完成 PyInstaller 构建并生成 `artifacts/capmaster-macos-<arch>-v<version>.tar.gz`。
- [ ] 构建结束后 `dist/capmaster` 可直接运行，并可使用 `scripts/tests/run_binary_smoke.sh dist/capmaster` 通过冒烟验证。
- [ ] `scripts/tests/run_binary_smoke.sh` 可针对最新产物通过基本 CLI 验证，并在 CI 中配置为发布前门槛。
- [ ] tarball 内容包含 `capmaster` 可执行文件与 `capmaster/resources/**`、`resources/services.txt` 等示例资源，解压后可在任意路径直接运行。
- [ ] 发布流程（构建→冒烟→手动命令→上传→Release Note）完整执行，并在 Release Note 中注明 `tshark` 依赖与资源目录说明。

---

通过以上流程即可稳定地将 CapMaster 打包为 macOS 单文件二进制，并在后续迭代中复用同一构建与验证步骤。