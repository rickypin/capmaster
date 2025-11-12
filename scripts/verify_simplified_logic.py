#!/usr/bin/env python3
"""
验证简化后的 TTL 判断逻辑与原逻辑等效

测试所有可能的场景，确保简化后的逻辑产生相同的结果。
"""


def original_logic(client_hops_a, server_hops_a, client_hops_b, server_hops_b):
    """原始的复杂逻辑（89行）"""
    client_delta_diff = client_hops_b - client_hops_a
    server_delta_diff = server_hops_a - server_hops_b

    # Scenario 1: Both client and server deltas agree
    if client_delta_diff > 0 and server_delta_diff > 0:
        return "A_CLOSER_TO_CLIENT"
    if client_delta_diff < 0 and server_delta_diff < 0:
        return "B_CLOSER_TO_CLIENT"

    # Scenario 2: Client and server deltas conflict (NAT scenario)
    if (client_delta_diff > 0 and server_delta_diff < 0) or \
       (client_delta_diff < 0 and server_delta_diff > 0):
        if server_delta_diff < 0:
            return "B_CLOSER_TO_CLIENT"
        else:
            return "A_CLOSER_TO_CLIENT"

    # Scenario 3: Only server-side judgment (client_delta_diff == 0)
    if server_delta_diff > 0:
        return "A_CLOSER_TO_CLIENT"
    elif server_delta_diff < 0:
        return "B_CLOSER_TO_CLIENT"

    return "SAME_POSITION"


def simplified_logic(client_hops_a, server_hops_a, client_hops_b, server_hops_b):
    """简化后的逻辑（23行核心逻辑）"""
    server_delta_diff = server_hops_a - server_hops_b
    
    if server_delta_diff > 0:
        return "A_CLOSER_TO_CLIENT"
    elif server_delta_diff < 0:
        return "B_CLOSER_TO_CLIENT"
    else:
        return "SAME_POSITION"


def test_all_scenarios():
    """测试所有可能的场景"""
    
    print("=" * 80)
    print("验证简化逻辑与原逻辑的等效性")
    print("=" * 80)
    
    # 测试场景：覆盖所有可能的 delta 组合
    test_cases = [
        # (client_delta_diff, server_delta_diff, 场景描述)
        (1, 1, "双方一致: A_CLOSER_TO_CLIENT"),
        (-1, -1, "双方一致: B_CLOSER_TO_CLIENT"),
        (1, -1, "冲突场景 (NAT): 使用 server -> B_CLOSER_TO_CLIENT"),
        (-1, 1, "冲突场景 (NAT): 使用 server -> A_CLOSER_TO_CLIENT"),
        (0, 1, "仅 server 判断: A_CLOSER_TO_CLIENT"),
        (0, -1, "仅 server 判断: B_CLOSER_TO_CLIENT"),
        (1, 0, "仅 client 判断: SAME_POSITION"),
        (-1, 0, "仅 client 判断: SAME_POSITION"),
        (0, 0, "无法判断: SAME_POSITION"),
    ]
    
    all_passed = True
    
    for client_delta, server_delta, description in test_cases:
        # 构造 hops 值
        client_hops_a = 5
        server_hops_a = 5
        client_hops_b = client_hops_a + client_delta
        server_hops_b = server_hops_a - server_delta
        
        original_result = original_logic(client_hops_a, server_hops_a, client_hops_b, server_hops_b)
        simplified_result = simplified_logic(client_hops_a, server_hops_a, client_hops_b, server_hops_b)
        
        passed = original_result == simplified_result
        all_passed = all_passed and passed
        
        status = "✅" if passed else "❌"
        
        print(f"\n{status} {description}")
        print(f"   client_delta={client_delta:2d}, server_delta={server_delta:2d}")
        print(f"   原逻辑: {original_result}")
        print(f"   简化后: {simplified_result}")
        
        if not passed:
            print(f"   ⚠️  结果不一致！")
    
    print("\n" + "=" * 80)
    if all_passed:
        print("✅ 所有测试通过！简化逻辑与原逻辑完全等效。")
    else:
        print("❌ 发现不一致！需要检查简化逻辑。")
    print("=" * 80)
    
    return all_passed


def test_real_world_scenarios():
    """测试真实世界的场景"""
    
    print("\n" + "=" * 80)
    print("真实场景测试")
    print("=" * 80)
    
    scenarios = [
        {
            "name": "场景 1: 正常网络 (Client → A → B → Server)",
            "client_hops_a": 2,
            "server_hops_a": 4,
            "client_hops_b": 4,
            "server_hops_b": 2,
            "expected": "A_CLOSER_TO_CLIENT",
        },
        {
            "name": "场景 2: 正常网络 (Client → B → A → Server)",
            "client_hops_a": 4,
            "server_hops_a": 2,
            "client_hops_b": 2,
            "server_hops_b": 4,
            "expected": "B_CLOSER_TO_CLIENT",
        },
        {
            "name": "场景 3: NAT 场景",
            "client_hops_a": 1,
            "server_hops_a": 2,
            "client_hops_b": 2,
            "server_hops_b": 4,
            "expected": "B_CLOSER_TO_CLIENT",
        },
        {
            "name": "场景 4: 用户实际数据 - Group 1",
            "client_hops_a": 6,
            "server_hops_a": 1,
            "client_hops_b": 6,
            "server_hops_b": 2,
            "expected": "B_CLOSER_TO_CLIENT",
        },
        {
            "name": "场景 5: 用户实际数据 - Group 2 (NAT)",
            "client_hops_a": 1,
            "server_hops_a": 1,
            "client_hops_b": 6,
            "server_hops_b": 2,
            "expected": "B_CLOSER_TO_CLIENT",
        },
        {
            "name": "场景 6: 所有 hops = 0",
            "client_hops_a": 0,
            "server_hops_a": 0,
            "client_hops_b": 0,
            "server_hops_b": 0,
            "expected": "SAME_POSITION",
        },
    ]
    
    all_passed = True
    
    for scenario in scenarios:
        client_hops_a = scenario["client_hops_a"]
        server_hops_a = scenario["server_hops_a"]
        client_hops_b = scenario["client_hops_b"]
        server_hops_b = scenario["server_hops_b"]
        expected = scenario["expected"]
        
        original_result = original_logic(client_hops_a, server_hops_a, client_hops_b, server_hops_b)
        simplified_result = simplified_logic(client_hops_a, server_hops_a, client_hops_b, server_hops_b)
        
        passed = (original_result == simplified_result == expected)
        all_passed = all_passed and passed
        
        status = "✅" if passed else "❌"
        
        print(f"\n{status} {scenario['name']}")
        print(f"   Hops: A(c={client_hops_a}, s={server_hops_a}), B(c={client_hops_b}, s={server_hops_b})")
        print(f"   期望: {expected}")
        print(f"   原逻辑: {original_result}")
        print(f"   简化后: {simplified_result}")
        
        if not passed:
            print(f"   ⚠️  结果不符合预期！")
    
    print("\n" + "=" * 80)
    if all_passed:
        print("✅ 所有真实场景测试通过！")
    else:
        print("❌ 发现问题！")
    print("=" * 80)
    
    return all_passed


if __name__ == "__main__":
    # 运行所有测试
    test1_passed = test_all_scenarios()
    test2_passed = test_real_world_scenarios()
    
    print("\n" + "=" * 80)
    print("总结")
    print("=" * 80)
    
    if test1_passed and test2_passed:
        print("\n✅ 简化逻辑验证成功！")
        print("\n代码行数对比:")
        print("  - 原逻辑: 89 行")
        print("  - 简化后: 23 行（核心逻辑）")
        print("  - 减少: 74%")
        print("\n优势:")
        print("  ✅ 逻辑清晰，易于理解")
        print("  ✅ 与原逻辑完全等效")
        print("  ✅ 明确表达设计意图：仅使用 Server 端 TTL")
        print("  ✅ 避免 NAT 场景的误判")
    else:
        print("\n❌ 验证失败！需要检查简化逻辑。")
    
    print("=" * 80)

