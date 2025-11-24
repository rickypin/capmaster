## CapMaster Topology 插件多协议扩展实现方案（UDP + ICMP type 3）

> 目标：在**不破坏现有 TCP pipeline 行为**的前提下，为单点拓扑增加 UDP Service 拓扑与 ICMP type 3 Unreachable 事件拓扑，用作后续实现与评审的技术基线。

---

## 1. 范围与非目标

### 1.1 本轮范围

- 仅影响 **topology 插件的单点拓扑**（`capmaster topology -i <pcap>`）：
  - **保留且不改变现有 TCP Service 拓扑** 的行为与输出；
  - 新增 **UDP Service 拓扑**（按 `(server_port, protocol=17)` 聚合）；
  - 新增 **ICMP type 3 Destination Unreachable 事件拓扑**，作为独立 section 输出；
  - 所有 TTL → hops 推断逻辑继续复用现有 `ttl_utils.most_common_hops`。

### 1.2 明确不做的事情（后续可扩展）

- 不修改现有 **TCP-only connection 抽取与 match/multi-capture pipeline**：
  - `capmaster/core/connection/connection_extractor.py::extract_connections_from_pcap` 仍然只抽取 TCP；
  - match 插件、双点拓扑（`TopologyAnalyzer`）保持 **TCP-only**。
- 不在本轮实现：
  - UDP 在双点拓扑中的比对与位置判断；
  - ICMP Echo（type 8/0, 0/0）路径拓扑（`IcmpEchoPath`）；
  - 任意形式的“把 ICMP 抽象成 Service”的输出。

---

## 2. 总体架构调整概览

### 2.1 总体思路

在现有代码中，**单点拓扑 pipeline 的核心入口** 是：

- `capmaster/plugins/topology/runner.py::_run_single_capture_pipeline`

当前行为：

1. 使用 `extract_connections_from_pcap()` 抽取 TCP 连接（`list[TcpConnection]`）。
2. 使用 `ServerDetector` 识别 server 端；在必要时对 client/server 方向和 TTL 进行交换。
3. 将所有 TCP 连接按 `(server_port, protocol)` 聚合成 `ServiceTopologyInfo` 列表。
4. 封装为 `SingleTopologyInfo`，传入 `format_single_topology` 输出。

本轮改动采用 **“并联扩展”** 策略：

- 保持上述 TCP pipeline 不变；
- 在 `_run_single_capture_pipeline` 内部旁路增加两条只在 topology 插件使用的分支：
  - **UDP 抽取与 Service 聚合分支**；
  - **ICMP type 3 Unreachable 事件抽取与聚合分支**；
- 最终将 TCP/UDP Service 统一放入 `services` 列表，将 ICMP type 3 事件放入 `icmp_unreachable_events` 列表。

### 2.2 新增数据结构与文件（概览）

1. **单点拓扑容器扩展**（保持向后兼容）：
   - 文件：`capmaster/plugins/topology/analysis.py`
   - 新增（或扩展）结构：
     - `@dataclass
       class IcmpUnreachableEventInfo: ...`
     - `@dataclass
       class SingleTopologyInfo:
           file_name: str
           services: list[ServiceTopologyInfo]
           icmp_unreachable_events: list[IcmpUnreachableEventInfo] = field(default_factory=list)`

2. **ICMP type 3 抽取与聚合专用模块**：
   - 建议新文件：`capmaster/plugins/topology/icmp_unreachable.py`
   - 内部结构示例：
     - `IcmpUnreachablePacket`（内部使用的数据载体）；
     - `IcmpUnreachableEvent`（面向 pipeline 的聚合结果）；
     - 抽取/聚合函数 `extract_icmp_unreachable_events(pcap_file: Path) -> list[IcmpUnreachableEvent]`。

3. **UDP 抽取与 Service 聚合模块**（命名可调整）：
   - 建议新文件：`capmaster/plugins/topology/udp_connections.py`；
   - 内部结构（保持实现简单、不过度建模）：
     - `UdpFieldExtractor`（基于 `TsharkWrapper` 的字段抽取封装）；
     - `UdpPacket`（tshark 行解析结果的数据载体）；
     - 抽取/聚合函数 `extract_udp_services_for_topology(pcap_file: Path) -> list[ServiceTopologyInfo]`（直接按 `dst_port` 聚合为 `ServiceTopologyInfo(protocol=17)`）。

---

## 3. UDP Service 拓扑实现方案（单点）

### 3.1 抽取层：从 PCAP 抽 UDP 报文

**不改动** `extract_connections_from_pcap()`，另起专用 UDP 抽取器，遵循项目既有模式：

- 参考：
  - `capmaster/core/connection/extractor.py::TcpFieldExtractor`；
  - `capmaster/core/connection/tls_extractor.py::TlsClientHelloExtractor`；
  - `capmaster/plugins/analyze/modules/udp_conversations.py::UdpConversationsModule`（已有 `-z conv,udp` 使用经验）。

**计划：**

1. 在 `udp_connections.py` 中定义 `UdpFieldExtractor`：
   - 通过 `TsharkWrapper` 调用 tshark：
     - `-Y "udp"` 过滤 UDP 报文；
     - 输出字段包括：
       - `frame.number`, `frame.time_epoch`；
       - `ip.proto`（应为 17）；
       - `ip.src`, `ip.dst`；
       - `udp.srcport`, `udp.dstport`；
       - `ip.ttl`；
       - 可选 payload 长度/MD5 字段（根据需要决定是否抽取）。
   - 将每行解析为 `UdpPacket`：
     - `stream_id` 字段可复用 `udp.stream`（如需要跨包关联）。

2. `UdpPacket` 字段建议：
   - `frame_number: int`
   - `timestamp: float`
   - `protocol: int`（固定 17，兼容多协议字段）
   - `src_ip: str`, `dst_ip: str`
   - `src_port: int`, `dst_port: int`
   - `ttl: int | None`
   - `stream_id: int | None`

### 3.2 聚合层：按 server_port 构造 UDP ServiceTopologyInfo

在 UDP 场景下，本轮**不引入 `UdpConnection`/`UdpConnectionBuilder` 级别的建模**，而是直接基于 `UdpPacket` 按端口聚合为 Service：

1. 以 `(server_port_candidate, protocol=17)` 为 key 聚合：

   - 默认认为 `dst_port` 是 server 端口（典型客户端 → 服务端模式）；
   - 如后续实践发现某些场景（例如 P2P、对等发现）经常反向，可在后续迭代中有针对性引入启发式，而不在本轮一次性实现。

2. 在聚合过程中为每个端口维护：

   - `client_ips: set[str]`：来自 `src_ip` 的集合；
   - `server_ips: set[str]`：来自 `dst_ip` 的集合；
   - `client_ttls: list[int]`：从 `src_ip` 一侧收集的 TTL；
   - `server_ttls: list[int]`：从 `dst_ip` 一侧收集的 TTL；
   - `connection_count: int`：可简单理解为“观测到的请求次数”，按实现选择“报文数”或 `(src_ip, src_port)` 去重后计数。

3. hops 推断：

   - 复用 `most_common_hops(client_ttls)` / `most_common_hops(server_ttls)`；
   - 当对应列表为空时，hops 记为 `None`。

4. 聚合完成后，为每个端口构造一个 `ServiceTopologyInfo` 实例：

   - `server_port` = 上述聚合 key 中的端口；
   - `protocol` = `17`（UDP）；
   - 其余字段含义与现有 TCP Service 拓扑保持一致。

> 如后续需要更细粒度的“UDP 会话”建模，可在未来迭代中再单独设计 `UdpConnection` 结构，而不在本轮强行复制 TCP 方案。

### 3.3 与现有 TCP Service 的合并

在 `runner._run_single_capture_pipeline` 中：

1. **保持现有 TCP service 聚合逻辑不变**（仍基于 `extract_connections_from_pcap()` 返回的 `TcpConnection` 列表和 `ServerDetector`）。
2. 在构造 `services` 列表之前或之后：
   - 调用 `extract_udp_services_for_topology(file_path)`；
   - 将返回的 UDP `ServiceTopologyInfo(protocol=17)` 追加到 `services` 列表；
3. 对合并后的 `services` 做统一排序并传入 `SingleTopologyInfo`：
   - 建议按 `(protocol, server_port)` 排序，或保持当前仅按 `server_port` 的行为，但需要在实现中保持稳定性。

> 重要边界：
>
> - 本轮变更仅作用于 **topology 插件的单点拓扑**；
> - match 插件、双点拓扑等逻辑保持 TCP-only，不在此次设计范围内改动。

## 4. ICMP type 3 Unreachable 事件拓扑实现方案（单点）

### 4.1 抽象：IcmpUnreachableEvent（非 Service）

ICMP 不再被抽象为 Service，而是单独的 **“不可达事件拓扑”**：

- 输出整体分成两部分：
  1. Service 拓扑（TCP/UDP）；
  2. ICMP 拓扑（仅 type 3 Unreachable 事件）。

- 聚合粒度由用户明确给出：

  > 按 `(client_ip, reporter_ip, icmp_code, inner_dst_ip, inner_protocol, inner_dst_port)` 聚合成一条事件

据此定义内部结构：

- `IcmpUnreachableEvent`（位于 `icmp_unreachable.py`）：
  - `client_ip: str`
  - `reporter_ip: str`
  - `icmp_code: int`
  - `inner_dst_ip: str`
  - `inner_protocol: int`
  - `inner_dst_port: int`
  - `count: int`（报文数）
  - `hops_from_reporter: int | None`（从 `reporter` 到 capture point 的 hops）

对应的展示结构：

- `IcmpUnreachableEventInfo`（位于 `analysis.py`，用于 formatter）：
  - 字段与上面一致，或仅做命名/类型轻微差异。

### 4.2 ICMP 抽取与 IcmpUnreachablePacket

在 `icmp_unreachable.py` 内，字段抽取策略要**与当前项目中 `IcmpStatsModule` 所使用的 tshark 字段保持一致**，避免依赖不存在的 `icmp.ip.*` 派生字段。

1. 使用 `TsharkWrapper` 执行 tshark，过滤与格式设置：
   - `-Y "icmp"`（先抽取所有 ICMP 报文，再在解析阶段筛选 `icmp.type == 3`）；
   - `-T fields`；
   - `-e icmp.type -e icmp.code -e ip.proto -e ip.src -e tcp.srcport -e udp.srcport -e ip.dst -e tcp.dstport -e udp.dstport`；
   - 追加：`-e ip.ttl`，用于估算 hops；
   - 输出控制与 `IcmpStatsModule.build_tshark_args()` 保持一致：
     - `-E occurrence=l`；
     - `-E separator=,`（所有字段以逗号分隔）。

2. 解析语义时的约定（结合我们在 `TC-001-5-20190905` 与 `TC-002-4-20211216` 上的实际观察）：
   - 对于 type 3 错误消息，这组字段表示“被 ICMP 报文嵌入的原始 IPv4+TCP/UDP 报文”的 5‑tuple 信息：
     - `ip.src` / `ip.dst`：视作**原始报文的源/目的 IP**；
     - `tcp.srcport` / `udp.srcport`：原始报文的源端口（TCP/UDP 二选一）；
     - `tcp.dstport` / `udp.dstport`：原始报文的目的端口（TCP/UDP 二选一）；
     - `ip.ttl`：来自封装片段中的 TTL 样本，用于后续粗略估算 hop 数（与 outer IP 头并不完全等价，因此仅作 heuristic 使用）。
   - 由于实际 tshark 版本不存在 `icmp.ip.dst` / `icmp.ip.proto` / `icmp.tcp.*` / `icmp.udp.*` 字段，本设计**不再依赖这些字段名**。

3. 基于上述输出，IcmpUnreachablePacket 内部字段建议为：
   - `client_ip: str`：原始报文的客户端 IP，等于 `ip.src`；
   - `reporter_ip: str | None`：发出 ICMP 的设备 IP（**预留字段**）。
     - 受限于当前字段集，我们目前**无法可靠获取 outer IP 头**，因此在实现中统一将 `reporter_ip` 置为 `None`，不参与任何文案展示，避免误导；
     - 如未来在 tshark 调用中增加并验证 outer IP 字段，可在实现中启用该字段并更新拓扑输出格式；
   - `icmp_code: int`：来自 `icmp.code`；
   - `inner_dst_ip: str`：原始报文的目的 IP，一般等于 `ip.dst`（与 `client_ip` 组合构成 inner 5‑tuple）；
   - `inner_protocol: int`：来自 `ip.proto`（6=TCP，17=UDP，其它视为“未知/暂不支持”）；
   - `inner_dst_port: int`：
     - 若存在 `tcp.dstport`，则取该值；
     - 否则若存在 `udp.dstport`，则取该值；
     - 否则置为 `0`，表示未知或不适用；
   - `ttl: int | None`：如实现中额外抽取 `ip.ttl`，则记录为整数，否则为 `None`。

4. 定义内部载体 `IcmpUnreachablePacket`：
   - 使用上述字段作为数据载体，便于后续按
     `(client_ip, reporter_ip, icmp_code, inner_dst_ip, inner_protocol, inner_dst_port)` 进行聚合（当前实现中 reporter_ip 始终为 None，不影响聚合结果）。

### 4.3 聚合函数：extract_icmp_unreachable_events

在 `icmp_unreachable.py` 中实现：

- `def extract_icmp_unreachable_events(pcap_file: Path) -> list[IcmpUnreachableEvent]:`

逻辑：

1. 遍历 tshark 解析出的 `IcmpUnreachablePacket` 序列；
2. 构造 key：
   - `key = (client_ip, reporter_ip, icmp_code, inner_dst_ip, inner_protocol, inner_dst_port)`；
3. 使用 `dict[key] -> agg` 聚合：
   - `agg.count += 1`；
   - 若 `ttl` 有效，`agg.ttls.append(ttl)`；
4. 最终对每个 key：
   - `hops_from_reporter = most_common_hops(agg.ttls)`（无 TTL 则为 `None`）；
   - 构造 `IcmpUnreachableEvent` 对象；
5. 返回的列表按稳定顺序排序（例如：`
   - `client_ip`, `inner_dst_ip`, `inner_protocol`, `inner_dst_port`, `icmp_code`）。

### 4.4 与单点 topology pipeline 的集成

在 `runner._run_single_capture_pipeline` 中：

1. 在完成 TCP/UDP Service 聚合后，调用：
   - `icmp_events = extract_icmp_unreachable_events(file_path)`；
2. 将其映射为 `IcmpUnreachableEventInfo` 列表：
   - 保留所有 key 字段与 `count/hops_from_reporter`；
3. 构造 `SingleTopologyInfo` 时一并传入：
   - `SingleTopologyInfo(file_name=..., services=services, icmp_unreachable_events=icmp_infos)`。

### 4.5 输出格式：新增 “ICMP Unreachable Events” section

在 `analysis.py::format_single_topology` 中：

1. 保持现有 Service 部分输出不变：
   - `=== Service N: Port X (TCP/UDP) === ...`
2. 在 Service 输出结束后，若 `icmp_unreachable_events` 非空，则追加：

   ```text
   === ICMP Unreachable Events ===
   Client 10.0.0.1 → 8.8.8.8 (UDP/53), reported by Unknown: code 3 (Port Unreachable), count=5
   Client 10.0.0.2 → 1.1.1.1 (TCP/443), reported by Unknown: code 1 (Host Unreachable), count=2
   ```

3. 具体字符串拼接可通过一个辅助函数实现：
   - `_format_icmp_unreachable_event_line(event: IcmpUnreachableEventInfo) -> str`；
   - 使用 `_format_protocol(event.inner_protocol)` 映射协议号为 `TCP/UDP/ICMP/...`。

---

## 5. 开发步骤与验证计划

### 5.1 推荐开发顺序

1. **实现 UDP 单点 Service 拓扑**：
   - [ ] 新建 `udp_connections.py`，实现 `UdpFieldExtractor` / `UdpPacket`；
   - [ ] 实现 `extract_udp_services_for_topology()`，按 `dst_port` 聚合为 `ServiceTopologyInfo(protocol=17)`；
   - [ ] 在 `runner._run_single_capture_pipeline` 中并入 UDP services；
   - [ ] 为包含 UDP 的 PCAP 增加/补充测试，验证 `Port X (UDP)` 正常展示。

2. **实现 ICMP type 3 Unreachable 事件拓扑**：
   - [ ] 新建 `icmp_unreachable.py`，实现 tshark 抽取与 `extract_icmp_unreachable_events()`；
   - [ ] 扩展 `analysis.py` 中的 `SingleTopologyInfo` 与新增 `IcmpUnreachableEventInfo`；
   - [ ] 在 `runner._run_single_capture_pipeline` 中并联调用 ICMP 分支；
   - [ ] 扩展 `format_single_topology`，输出 `=== ICMP Unreachable Events ===` section；
   - [ ] 为包含 ICMP type 3 报文的 PCAP 增加/补充测试，验证聚合 key 与 hops 展示符合预期。

3. **回归与兼容性检查**：
   - [ ] 运行现有 topology 相关测试，确认纯 TCP 场景输出未发生语义变更；
   - [ ] 对典型 PCAP（仅 TCP / TCP+UDP / TCP+UDP+ICMP）人工检视 CLI 输出，确认文案与结构符合预期设计。

### 5.2 风险点与缓解措施

- **tshark 字段名与版本差异风险**：
  - 缓解：
    - 在实现阶段通过样例 PCAP 实际跑一遍 tshark 命令，确认 `icmp.ip.*` / `icmp.tcp.*` / `icmp.udp.*` 等字段名；
    - 对解析失败场景给出安全默认值（如 `inner_dst_port=0`），并在日志中以 debug 级别记录。

- **UDP 角色识别误判风险**：
  - 本轮采用 **保守 heuristics（well-known 端口优先）**，对不明显的会话可以：
    - 选择直接跳过（不进入 Service 拓扑）；或
    - 标记为低 confidence，但仍合并统计。
  - 具体策略可在实现阶段根据样例 PCAP 迭代调整。

- **文件行数限制（单文件 ≤ 500 行）**：
  - 在新增文件时注意控制体积，必要时拆分成多个小模块（例如将 UDP 抽取与 server 检测拆成两个文件）。

---

本方案可作为后续实现与 code review 的统一参考，请在实现过程中严格对照本设计，任何偏离点建议在 PR 描述中说明原因与影响范围。
