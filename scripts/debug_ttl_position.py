#!/usr/bin/env python3
"""
调试 TTL 位置判断逻辑

分析为什么 group.txt 中 pcap_id=1 的 Server 侧 net_area 是空的
"""

import json


def determine_network_position(client_hops_a, server_hops_a, client_hops_b, server_hops_b):
    """
    复制自 db_writer.py 的逻辑（简化版本 - 方案2）

    使用 server-side TTL 作为主要判断标准，
    client-side TTL 仅用于一致性验证和日志记录。
    """
    # Calculate TTL delta differences
    client_delta_diff = client_hops_b - client_hops_a
    server_delta_diff = server_hops_a - server_hops_b

    # Detect potential NAT scenario (client and server deltas conflict)
    is_nat_scenario = (
        (client_delta_diff > 0 and server_delta_diff < 0) or
        (client_delta_diff < 0 and server_delta_diff > 0)
    )

    if is_nat_scenario:
        print(f"    [DEBUG] NAT scenario detected: client_delta={client_delta_diff}, "
              f"server_delta={server_delta_diff}. Using server-side TTL only.")

    # Always use server-side TTL for final judgment
    if server_delta_diff > 0:
        # A has more hops to server → A is farther from server → A closer to client
        return "A_CLOSER_TO_CLIENT"
    elif server_delta_diff < 0:
        # B has more hops to server → B is farther from server → B closer to client
        return "B_CLOSER_TO_CLIENT"
    else:
        # Same distance to server or cannot determine
        return "SAME_POSITION"


def analyze_group_txt():
    """分析 group.txt 中的 net_area 标记"""
    
    print("=" * 80)
    print("分析 group.txt 中的 net_area 标记")
    print("=" * 80)
    
    with open('group.txt', 'r') as f:
        lines = [json.loads(line.strip()) for line in f if line.strip()]
    
    # 按 group_id 分组
    groups = {}
    for record in lines:
        group_id = record['group_id']
        if group_id not in groups:
            groups[group_id] = []
        groups[group_id].append(record)
    
    # 分析每个 group
    for group_id in sorted(groups.keys()):
        print(f"\n{'='*80}")
        print(f"Group {group_id}")
        print(f"{'='*80}")
        
        group_records = groups[group_id]
        
        # 提取 Client 和 Server 节点
        pcap_0_client = next((r for r in group_records if r['pcap_id'] == 0 and r['type'] == 1), None)
        pcap_0_server = next((r for r in group_records if r['pcap_id'] == 0 and r['type'] == 2), None)
        pcap_1_client = next((r for r in group_records if r['pcap_id'] == 1 and r['type'] == 1), None)
        pcap_1_server = next((r for r in group_records if r['pcap_id'] == 1 and r['type'] == 2), None)
        
        print("\n当前 net_area 标记:")
        if pcap_0_client:
            print(f"  pcap_id=0, Client: net_area={pcap_0_client.get('net_area', [])}")
        if pcap_0_server:
            print(f"  pcap_id=0, Server: net_area={pcap_0_server.get('net_area', [])}")
        if pcap_1_client:
            print(f"  pcap_id=1, Client: net_area={pcap_1_client.get('net_area', [])}")
        if pcap_1_server:
            print(f"  pcap_1, Server: net_area={pcap_1_server.get('net_area', [])}")
        
        # 检查是否符合要求
        pcap_0_has_mark = (pcap_0_client and pcap_0_client.get('net_area')) or \
                          (pcap_0_server and pcap_0_server.get('net_area'))
        pcap_1_has_mark = (pcap_1_client and pcap_1_client.get('net_area')) or \
                          (pcap_1_server and pcap_1_server.get('net_area'))
        
        print("\n检查结果:")
        print(f"  pcap_id=0 有标记: {'✅' if pcap_0_has_mark else '❌'}")
        print(f"  pcap_id=1 有标记: {'✅' if pcap_1_has_mark else '❌'}")
        
        if not pcap_1_has_mark:
            print("\n  ❌ 问题: pcap_id=1 没有任何 net_area 标记！")
            print("     期望: pcap_id=1 的 Server 侧应该标记为 [0]")


def test_ttl_scenarios():
    """测试不同的 TTL 场景"""
    
    print("\n" + "=" * 80)
    print("测试不同的 TTL 场景")
    print("=" * 80)
    
    scenarios = [
        {
            "name": "场景 1: 所有 hops 都是 0",
            "client_hops_a": 0,
            "server_hops_a": 0,
            "client_hops_b": 0,
            "server_hops_b": 0,
        },
        {
            "name": "场景 2: B_CLOSER_TO_CLIENT (正常)",
            "client_hops_a": 4,
            "server_hops_a": 2,
            "client_hops_b": 2,
            "server_hops_b": 4,
        },
        {
            "name": "场景 3: NAT 场景 (旧逻辑会失效)",
            "client_hops_a": 1,
            "server_hops_a": 2,
            "client_hops_b": 2,
            "server_hops_b": 4,
        },
        {
            "name": "场景 4: 用户实际数据 - Group 1",
            "client_hops_a": 6,
            "server_hops_a": 1,
            "client_hops_b": 6,
            "server_hops_b": 2,
            "note": "File A: Client=58(hops=6), Server=63(hops=1)\n" +
                    "        File B: Client=58(hops=6), Server=62(hops=2)\n" +
                    "        实际拓扑: Client → B → A → Server"
        },
        {
            "name": "场景 5: 用户实际数据 - Group 2",
            "client_hops_a": 1,
            "server_hops_a": 1,
            "client_hops_b": 6,
            "server_hops_b": 2,
            "note": "File A: Client=63(hops=1), Server=63(hops=1)\n" +
                    "        File B: Client=58(hops=6), Server=62(hops=2)\n" +
                    "        实际拓扑: Client → B → A → Server"
        },
        {
            "name": "场景 6: 用户实际数据 - Group 4",
            "client_hops_a": 0,
            "server_hops_a": 1,
            "client_hops_b": 6,
            "server_hops_b": 2,
            "note": "File A: Client=64(hops=0), Server=63(hops=1)\n" +
                    "        File B: Client=58(hops=6), Server=62(hops=2)\n" +
                    "        实际拓扑: Client → B → A → Server"
        },
    ]
    
    for scenario in scenarios:
        print(f"\n{scenario['name']}")
        print("-" * 80)

        if 'note' in scenario:
            print(f"  说明: {scenario['note']}")
            print()

        client_hops_a = scenario['client_hops_a']
        server_hops_a = scenario['server_hops_a']
        client_hops_b = scenario['client_hops_b']
        server_hops_b = scenario['server_hops_b']

        position = determine_network_position(
            client_hops_a, server_hops_a, client_hops_b, server_hops_b
        )

        client_delta_diff = client_hops_b - client_hops_a
        server_delta_diff = server_hops_a - server_hops_b

        print(f"  client_hops_a={client_hops_a}, server_hops_a={server_hops_a}")
        print(f"  client_hops_b={client_hops_b}, server_hops_b={server_hops_b}")
        print(f"  client_delta_diff={client_delta_diff}, server_delta_diff={server_delta_diff}")

        # 判断是否是冲突场景（NAT）
        is_conflict = (client_delta_diff > 0 and server_delta_diff < 0) or \
                      (client_delta_diff < 0 and server_delta_diff > 0)

        if is_conflict:
            print(f"  ⚠️  检测到冲突: Client 和 Server 端判断不一致 (可能是 NAT)")
            print(f"  → 使用 Server 端 TTL 判断")

        print(f"  判断结果: {position}")
        
        # 根据 position 确定 net_area
        pcap_id_a = 0
        pcap_id_b = 1
        
        net_area_a_client = []
        net_area_a_server = []
        net_area_b_client = []
        net_area_b_server = []
        
        if position == "A_CLOSER_TO_CLIENT":
            # Client -> A -> B -> Server
            net_area_a_server = [pcap_id_b]
            net_area_b_client = [pcap_id_a]
        elif position == "B_CLOSER_TO_CLIENT":
            # Client -> B -> A -> Server
            net_area_b_server = [pcap_id_a]
            net_area_a_client = [pcap_id_b]
        
        print(f"\n  net_area 标记:")
        print(f"    pcap_id=0, Client: {net_area_a_client}")
        print(f"    pcap_id=0, Server: {net_area_a_server}")
        print(f"    pcap_id=1, Client: {net_area_b_client}")
        print(f"    pcap_id=1, Server: {net_area_b_server}")
        
        # 检查是否符合要求
        pcap_0_ok = bool(net_area_a_client or net_area_a_server)
        pcap_1_ok = bool(net_area_b_client or net_area_b_server)
        
        print(f"\n  检查:")
        print(f"    pcap_id=0 有标记: {'✅' if pcap_0_ok else '❌'}")
        print(f"    pcap_id=1 有标记: {'✅' if pcap_1_ok else '❌'}")


if __name__ == "__main__":
    analyze_group_txt()
    test_ttl_scenarios()
    
    print("\n" + "=" * 80)
    print("结论")
    print("=" * 80)
    print("\n如果 group.txt 中 pcap_id=1 的 Server 侧 net_area 是空的，")
    print("最可能的原因是 TTL 判断返回了 'SAME_POSITION'（所有 hops 都是 0）")
    print("\n这意味着当前的 TTL 判断逻辑在这个案例中失效了。")

