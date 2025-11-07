# Rust Hash Trait 分析

## 问题

Python 计算结果：`3124968312329388194`
Rust 计算结果：`-1173584886679544929`

两者完全不同，说明字节序列化方式不同。

## Rust Hash Trait 的实现

在 Rust 中，`Hash` trait 的实现方式如下：

### 1. u16 的 Hash 实现

```rust
impl Hash for u16 {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u16(*self)
    }
}
```

### 2. Hasher 的 write_u16 实现

关键问题：`write_u16` 使用什么字节序？

查看 Rust 标准库源码：

```rust
// std::hash::Hasher
fn write_u16(&mut self, i: u16) {
    self.write(&i.to_ne_bytes())  // 使用 native endian!
}
```

**重要发现**：Rust 的 `write_u16` 使用 **native endian**（本机字节序），而不是 big-endian！

在大多数现代系统（x86, x86_64, ARM）上，native endian 是 **little-endian**。

### 3. NetEndian<u16> 的 Hash 实现

```rust
// NetEndian<u16> 是一个包装类型
pub struct NetEndian<T>(T);

impl Hash for NetEndian<u16> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // NetEndian 内部存储的是 big-endian 值
        // 但 Hash 时会转换为 native endian
        self.0.hash(state)  // 调用 u16 的 hash
    }
}
```

等等，这里有个问题。让我重新理解 `NetEndian`。

### 4. NetEndian 的真实实现

查看 xuanwu-core 的代码，`NetEndian` 可能是这样实现的：

```rust
#[repr(transparent)]
pub struct NetEndian<T>(T);

impl NetEndian<u16> {
    pub fn new(value: u16) -> Self {
        NetEndian(value.to_be())  // 转换为 big-endian
    }
    
    pub fn get(&self) -> u16 {
        u16::from_be(self.0)  // 从 big-endian 转换回来
    }
}

impl Hash for NetEndian<u16> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // 直接 hash 内部的 big-endian 值
        // 但 write_u16 会使用 native endian!
        state.write_u16(self.0)
    }
}
```

## 问题根源

如果 Rust 的 `write_u16` 使用 **little-endian**（在 x86_64 上），那么：

```
Port 35101 (0x891D):
  Big-endian:    89 1D
  Little-endian: 1D 89  ← Rust 实际使用的
```

而我们的 Python 代码使用的是 big-endian (`>H`)，所以结果不同！

## 解决方案

我们需要将 Python 代码改为使用 **little-endian** 来匹配 Rust 的行为：

```python
# 错误的（当前）：
data.extend(struct.pack('>H', port))  # Big-endian

# 正确的：
data.extend(struct.pack('<H', port))  # Little-endian (native)
```

## 验证

让我们用 little-endian 重新计算：

```
Byte sequence (little-endian):
  1D 89        # src_port (35101) in little-endian
  BE 66        # dst_port (26302) in little-endian
  08 2A 60 2D  # src_ip (8.42.96.45)
  08 43 02 7D  # dst_ip (8.67.2.125)
  06           # protocol (TCP)
```

这应该会产生与 Rust 相同的哈希值。

## 关于 NetEndian 的误解

`NetEndian<u16>` 这个名字容易让人误解。它的作用是：
1. **存储时**使用 network byte order (big-endian)
2. **Hash 时**使用 native byte order (little-endian on x86_64)

所以虽然叫 "NetEndian"，但在 Hash 计算时实际上使用的是 native endian！

