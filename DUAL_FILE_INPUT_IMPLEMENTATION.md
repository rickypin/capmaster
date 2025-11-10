# 双文件输入功能实现总结

## 概述

成功为 `match` 插件添加了与 `compare` 插件一致的双文件输入支持，采用方案 C（混合方案），将公共代码提取到 `capmaster/utils/` 目录。

## 实施方案

### 方案 C：混合方案（装饰器 + 解析器）

**优点**：
- ✅ 代码复用最大化
- ✅ 职责清晰（CLI 层和业务层分离）
- ✅ 易于测试
- ✅ 符合项目结构
- ✅ 避免过度工程化

## 新增文件

### 1. `capmaster/utils/cli_options.py`

提供 Click 装饰器和验证函数：

- **`dual_file_input_options`** 装饰器：自动添加 5 个 CLI 参数
  - `-i/--input`
  - `--file1`
  - `--file1-pcapid`
  - `--file2`
  - `--file2-pcapid`

- **`validate_dual_file_input`** 函数：验证参数有效性
  - 互斥性检查（不能同时使用 `-i` 和 `--file1/--file2`）
  - 完整性检查（必须提供一种输入方式）
  - 参数完整性检查（使用 `--file1/--file2` 时必须提供 pcapid）
  - 值范围检查（pcapid 必须是 0 或 1）

### 2. `capmaster/utils/input_parser.py`

提供输入解析工具：

- **`DualFileInput`** 数据类：统一的双文件输入结构
  - `file1`: 第一个文件（baseline）
  - `file2`: 第二个文件（compare）
  - `pcap_id_mapping`: 可选的 PCAP ID 映射（仅在使用 `--file1/--file2` 时存在）
  - 提供 `baseline_file` 和 `compare_file` 属性别名

- **`DualFileInputParser`** 类：解析双文件输入参数
  - 支持两种输入方式
  - 返回统一的 `DualFileInput` 对象

## 修改文件

### `capmaster/plugins/match/plugin.py`

**主要修改**：

1. **导入新模块**：
   ```python
   from capmaster.utils.cli_options import dual_file_input_options, validate_dual_file_input
   from capmaster.utils.input_parser import DualFileInputParser
   ```

2. **使用装饰器**：
   ```python
   @cli_group.command(name=self.name)
   @dual_file_input_options  # 一行代码添加所有参数
   @click.option("-o", "--output", ...)
   ```

3. **更新命令函数签名**：
   添加 5 个新参数：`input_path`, `file1`, `file1_pcapid`, `file2`, `file2_pcapid`

4. **添加参数验证**：
   ```python
   validate_dual_file_input(ctx, input_path, file1, file2, file1_pcapid, file2_pcapid)
   ```

5. **更新 execute 方法**：
   - 添加新参数到方法签名
   - 使用 `DualFileInputParser.parse()` 解析输入
   - 替换原有的文件扫描逻辑

6. **更新文档字符串**：
   - 添加 `--file1/--file2` 使用示例
   - 更新输入说明

## 功能特性

### 支持的输入方式

#### 方式 1：传统 `-i/--input` 方式（向后兼容）

```bash
# 目录方式
capmaster match -i captures/

# 逗号分隔文件列表
capmaster match -i "file1.pcap,file2.pcap"
```

#### 方式 2：新增 `--file1/--file2` 方式

```bash
# 显式指定文件和 PCAP ID
capmaster match --file1 a.pcap --file1-pcapid 0 --file2 b.pcap --file2-pcapid 1
```

### 参数验证

- ❌ 不能同时使用两种方式
- ❌ 必须提供一种方式
- ❌ 使用 `--file1/--file2` 时必须同时提供两个文件
- ❌ 使用 `--file1/--file2` 时必须提供对应的 pcapid
- ❌ pcapid 必须是 0 或 1

### 日志输出

使用 `--file1/--file2` 方式时，会额外输出 PCAP ID 映射信息：

```
INFO     File 1: TC-034-9-20230222-S-A-nginx.pcap
INFO     File 2: TC-034-9-20230222-S-B-server.pcap
INFO     PCAP ID mapping: TC-034-9-20230222-S-A-nginx.pcap -> 0, TC-034-9-20230222-S-B-server.pcap -> 1
INFO     Matching: TC-034-9-20230222-S-A-nginx.pcap <-> TC-034-9-20230222-S-B-server.pcap
```

## 测试验证

### 测试用例

✅ **帮助信息**：新参数正确显示
```bash
capmaster match --help
```

✅ **缺少输入**：正确报错
```bash
capmaster match
# Error: Must provide either -i/--input or both --file1 and --file2
```

✅ **互斥性检查**：正确报错
```bash
capmaster match -i test.pcap --file1 a.pcap
# Error: Cannot use both -i/--input and --file1/--file2 at the same time
```

✅ **参数不完整**：正确报错
```bash
capmaster match --file1 a.pcap
# Error: Must provide either -i/--input or both --file1 and --file2
```

✅ **缺少 pcapid**：正确报错
```bash
capmaster match --file1 a.pcap --file2 b.pcap
# Error: Both --file1-pcapid and --file2-pcapid must be provided when using --file1/--file2
```

✅ **pcapid 值错误**：正确报错
```bash
capmaster match --file1 a.pcap --file1-pcapid 2 --file2 b.pcap --file2-pcapid 0
# Error: --file1-pcapid must be 0 or 1
```

✅ **正确使用 --file1/--file2**：功能正常
```bash
capmaster match --file1 a.pcap --file1-pcapid 0 --file2 b.pcap --file2-pcapid 1
```

✅ **传统 -i 方式**：向后兼容，功能正常
```bash
capmaster match -i "a.pcap,b.pcap"
```

## 代码质量

- ✅ 无语法错误
- ✅ 类型注解完整
- ✅ 文档字符串完整
- ✅ 遵循项目代码风格
- ✅ 避免过度工程化

## 未来扩展

如果其他插件需要类似功能，可以直接复用：

```python
from capmaster.utils.cli_options import dual_file_input_options, validate_dual_file_input
from capmaster.utils.input_parser import DualFileInputParser

@cli_group.command()
@dual_file_input_options
@click.pass_context
def my_command(ctx, input_path, file1, file1_pcapid, file2, file2_pcapid, ...):
    validate_dual_file_input(ctx, input_path, file1, file2, file1_pcapid, file2_pcapid)
    dual_input = DualFileInputParser.parse(input_path, file1, file2, file1_pcapid, file2_pcapid)
    # ... 使用 dual_input.file1, dual_input.file2, dual_input.pcap_id_mapping
```

## 总结

成功实施方案 C，为 `match` 插件添加了与 `compare` 插件一致的双文件输入支持。实现过程中：

1. ✅ 创建了可复用的公共代码
2. ✅ 保持了向后兼容性
3. ✅ 遵循了实用主义原则
4. ✅ 避免了过度工程化
5. ✅ 通过了完整的功能测试

代码简洁、职责清晰、易于维护和扩展。

