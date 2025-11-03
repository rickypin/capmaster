#!/usr/bin/env python3
"""
对比原脚本和新脚本的匹配结果
找出新脚本独有的匹配，供人工验证
"""

import re
import sys
from pathlib import Path


def parse_old_script_matches(file_path):
    """解析原脚本的匹配结果"""
    matches = []
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
        
    # 匹配格式: [1] A: 10.0.0.104:35101 -> 10.116.133.7:10007
    pattern = r'\[(\d+)\]\s+A:\s+([\d.]+):(\d+)\s+->\s+([\d.]+):(\d+)'
    
    for match in re.finditer(pattern, content):
        idx = int(match.group(1))
        src_ip = match.group(2)
        src_port = match.group(3)
        dst_ip = match.group(4)
        dst_port = match.group(5)
        
        # 创建唯一标识符（使用五元组）
        key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        matches.append((idx, key))
    
    return matches


def parse_new_script_output(output_text):
    """解析新脚本的输出"""
    matches = []
    
    # 匹配格式: [1] A: 10.0.0.104 -> 10.116.133.7:10007
    pattern = r'\[(\d+)\]\s+A:\s+([\d.]+)\s+->\s+([\d.]+):(\d+)'
    
    for match in re.finditer(pattern, output_text):
        idx = int(match.group(1))
        src_ip = match.group(2)
        dst_ip = match.group(3)
        dst_port = match.group(4)
        
        # 新脚本没有显示源端口，所以我们只用目标信息作为标识
        key = f"{src_ip}->*{dst_ip}:{dst_port}"
        matches.append((idx, key, src_ip, dst_ip, dst_port))
    
    return matches


def main():
    # 解析原脚本结果
    old_file = Path("cases/TC-034-3-20210604-O/statistics/correlations.txt")
    if not old_file.exists():
        print(f"错误: 找不到原脚本输出文件: {old_file}")
        return 1
    
    old_matches = parse_old_script_matches(old_file)
    print(f"原脚本匹配数: {len(old_matches)}")
    
    # 由于新脚本输出太长，我们需要重新运行并保存到文件
    print("\n请先运行以下命令保存新脚本输出:")
    print("python -m capmaster match -i cases/TC-034-3-20210604-O > /tmp/new_script_output.txt 2>&1")
    print("\n然后再运行此脚本进行对比")
    
    # 检查是否已经有新脚本输出
    new_output_file = Path("/tmp/new_script_output.txt")
    if not new_output_file.exists():
        return 0
    
    with open(new_output_file, 'r') as f:
        new_output = f.read()
    
    new_matches = parse_new_script_output(new_output)
    print(f"新脚本匹配数: {len(new_matches)}")
    
    # 提取原脚本的源IP集合（忽略端口）
    old_src_ips = set()
    for idx, key in old_matches:
        # key格式: "10.0.0.104:35101->10.116.133.7:10007"
        src_part = key.split('->')[0]
        src_ip = src_part.split(':')[0]
        old_src_ips.add(src_ip)
    
    # 找出新脚本独有的匹配（基于源IP）
    new_only = []
    for idx, key, src_ip, dst_ip, dst_port in new_matches:
        # 简化对比：只看源IP是否在原脚本中出现过
        # 这不是完美的对比，但可以快速找出可疑的匹配
        if src_ip not in old_src_ips:
            new_only.append((idx, src_ip, dst_ip, dst_port))
    
    print(f"\n新脚本独有的匹配（基于源IP）: {len(new_only)}")
    
    if new_only:
        print("\n前20个新脚本独有的匹配（供人工验证）:")
        print("=" * 80)
        for idx, src_ip, dst_ip, dst_port in new_only[:20]:
            print(f"[{idx}] A: {src_ip} -> {dst_ip}:{dst_port}")
        
        # 保存完整列表到文件
        output_file = Path("/tmp/new_only_matches.txt")
        with open(output_file, 'w') as f:
            for idx, src_ip, dst_ip, dst_port in new_only:
                f.write(f"[{idx}] A: {src_ip} -> {dst_ip}:{dst_port}\n")
        print(f"\n完整列表已保存到: {output_file}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

