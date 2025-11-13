#!/usr/bin/env python3
"""
分析 match 插件并行化的实际开销

这个脚本模拟了 match 插件的实际场景，展示为什么并行化不是最优解。
"""

import time
import pickle
import sys
from dataclasses import dataclass
from typing import List
from multiprocessing import Pool


@dataclass
class MockConnection:
    """模拟 TcpConnection 对象"""
    stream_id: int
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    ipid_set: set
    syn_options: str
    payload_hash: str
    
    def __sizeof__(self):
        """估算对象大小"""
        return (
            sys.getsizeof(self.stream_id) +
            sys.getsizeof(self.client_ip) +
            sys.getsizeof(self.server_ip) +
            sys.getsizeof(self.client_port) +
            sys.getsizeof(self.server_port) +
            sys.getsizeof(self.ipid_set) +
            sys.getsizeof(self.syn_options) +
            sys.getsizeof(self.payload_hash)
        )


def create_mock_connections(count: int) -> List[MockConnection]:
    """创建模拟连接数据"""
    connections = []
    for i in range(count):
        conn = MockConnection(
            stream_id=i,
            client_ip=f"192.168.1.{i % 255}",
            server_ip=f"10.0.0.{i % 255}",
            client_port=50000 + i,
            server_port=80 if i % 2 == 0 else 443,
            ipid_set=set(range(i, i + 100)),
            syn_options="mss1460,nop,nop,sackOK",
            payload_hash=f"hash_{i:08x}"
        )
        connections.append(conn)
    return connections


def simple_score(conn1: MockConnection, conn2: MockConnection) -> float:
    """简化的评分函数（模拟实际的 ConnectionScorer.score）"""
    score = 0.0
    
    # 端口检查
    if conn1.server_port == conn2.server_port:
        score += 0.2
    
    # IPID 重叠检查
    ipid_overlap = len(conn1.ipid_set & conn2.ipid_set)
    if ipid_overlap >= 3:
        score += 0.3
    
    # SYN 选项匹配
    if conn1.syn_options == conn2.syn_options:
        score += 0.2
    
    # Payload hash 匹配
    if conn1.payload_hash == conn2.payload_hash:
        score += 0.3
    
    return score


def match_connections_single(conns1: List[MockConnection], 
                             conns2: List[MockConnection]) -> List[tuple]:
    """单线程匹配（当前实现）"""
    matches = []
    for conn1 in conns1:
        for conn2 in conns2:
            score = simple_score(conn1, conn2)
            if score > 0.5:
                matches.append((conn1.stream_id, conn2.stream_id, score))
    return matches


def match_bucket(args):
    """多进程工作函数"""
    conns1, conns2 = args
    return match_connections_single(conns1, conns2)


def analyze_serialization_overhead(connections: List[MockConnection]):
    """分析序列化开销"""
    print(f"\n{'='*60}")
    print("序列化开销分析")
    print(f"{'='*60}")
    
    # 计算对象大小
    total_size = sum(sys.getsizeof(conn) for conn in connections)
    print(f"连接对象总大小: {total_size / 1024 / 1024:.2f} MB")
    
    # 测试序列化时间
    start = time.time()
    serialized = pickle.dumps(connections)
    serialize_time = time.time() - start
    print(f"序列化时间: {serialize_time:.3f} 秒")
    print(f"序列化后大小: {len(serialized) / 1024 / 1024:.2f} MB")
    
    # 测试反序列化时间
    start = time.time()
    deserialized = pickle.loads(serialized)
    deserialize_time = time.time() - start
    print(f"反序列化时间: {deserialize_time:.3f} 秒")
    
    total_ipc_overhead = serialize_time + deserialize_time
    print(f"总 IPC 开销: {total_ipc_overhead:.3f} 秒")
    
    return total_ipc_overhead


def benchmark_matching(conn_count: int):
    """基准测试"""
    print(f"\n{'='*60}")
    print(f"匹配性能基准测试（每侧 {conn_count} 个连接）")
    print(f"{'='*60}")
    
    # 创建测试数据
    print("创建测试数据...")
    conns1 = create_mock_connections(conn_count)
    conns2 = create_mock_connections(conn_count)
    
    # 分析序列化开销
    ipc_overhead = analyze_serialization_overhead(conns1 + conns2)
    
    # 单线程匹配
    print(f"\n{'='*60}")
    print("单线程匹配")
    print(f"{'='*60}")
    start = time.time()
    matches_single = match_connections_single(conns1, conns2)
    single_time = time.time() - start
    print(f"匹配时间: {single_time:.3f} 秒")
    print(f"找到匹配: {len(matches_single)} 对")
    
    # 多进程匹配（模拟 4 个桶）
    print(f"\n{'='*60}")
    print("多进程匹配（4 个进程，模拟 4 个桶）")
    print(f"{'='*60}")
    
    # 将连接分成 4 个桶
    bucket_size = len(conns1) // 4
    buckets = []
    for i in range(4):
        start_idx = i * bucket_size
        end_idx = start_idx + bucket_size if i < 3 else len(conns1)
        buckets.append((conns1[start_idx:end_idx], conns2))
    
    start = time.time()
    with Pool(processes=4) as pool:
        results = pool.map(match_bucket, buckets)
    multi_time = time.time() - start
    
    matches_multi = []
    for result in results:
        matches_multi.extend(result)
    
    print(f"匹配时间: {multi_time:.3f} 秒")
    print(f"找到匹配: {len(matches_multi)} 对")
    
    # 性能对比
    print(f"\n{'='*60}")
    print("性能对比")
    print(f"{'='*60}")
    print(f"单线程时间:     {single_time:.3f} 秒")
    print(f"多进程时间:     {multi_time:.3f} 秒")
    print(f"IPC 开销估算:   {ipc_overhead * 4:.3f} 秒 (4 个进程)")
    print(f"实际加速比:     {single_time / multi_time:.2f}x")
    print(f"理论加速比:     4.00x (4 个进程)")
    
    # 结论
    print(f"\n{'='*60}")
    print("结论")
    print(f"{'='*60}")
    
    if multi_time < single_time * 0.7:
        print("✅ 多进程有明显加速")
    elif multi_time < single_time:
        print("⚠️  多进程有轻微加速，但收益有限")
    else:
        print("❌ 多进程反而更慢，IPC 开销抵消了并行收益")
    
    print(f"\n对于 match 插件：")
    print(f"- 实际连接数通常更多（数万个）")
    print(f"- TcpConnection 对象更复杂（包含数据包列表）")
    print(f"- IPC 开销会更大")
    print(f"- 优化算法（Bucketing、预过滤）比并行化更有效")


def main():
    """主函数"""
    print("="*60)
    print("Match 插件并行化分析")
    print("="*60)
    
    # 测试不同规模的数据集
    for conn_count in [100, 500, 1000]:
        benchmark_matching(conn_count)
        print("\n")


if __name__ == "__main__":
    main()

