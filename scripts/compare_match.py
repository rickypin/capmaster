#!/usr/bin/env python3
"""
对比测试脚本：比较新旧 match 实现的结果

用法:
    python scripts/compare_match.py <case_dir>
    python scripts/compare_match.py --all  # 测试所有双文件案例
"""

import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple
import re
import json


class MatchResult:
    """Match 结果数据结构"""
    
    def __init__(self, output: str):
        self.output = output
        self.matches = self._parse_matches(output)
        self.total_connections = self._parse_total_connections(output)
        self.matched_count = len(self.matches)
    
    def _parse_matches(self, output: str) -> List[Tuple[int, int, int]]:
        """解析匹配结果: [(stream1, stream2, score), ...]"""
        matches = []
        # 匹配格式: "tcp.stream==123 <-> tcp.stream==456 (score: 85)"
        pattern = r'tcp\.stream==(\d+)\s*<->\s*tcp\.stream==(\d+)\s*\(score:\s*(\d+)\)'
        for match in re.finditer(pattern, output):
            stream1 = int(match.group(1))
            stream2 = int(match.group(2))
            score = int(match.group(3))
            matches.append((stream1, stream2, score))
        return matches
    
    def _parse_total_connections(self, output: str) -> Tuple[int, int]:
        """解析总连接数: (file1_count, file2_count)"""
        # 匹配格式: "File 1: 123 connections"
        pattern1 = r'File 1:\s*(\d+)\s+connections'
        pattern2 = r'File 2:\s*(\d+)\s+connections'
        
        match1 = re.search(pattern1, output)
        match2 = re.search(pattern2, output)
        
        count1 = int(match1.group(1)) if match1 else 0
        count2 = int(match2.group(1)) if match2 else 0
        
        return (count1, count2)


def run_old_script(case_dir: Path) -> MatchResult:
    """运行原始 shell 脚本"""
    script = Path("match_tcp_conns.sh")
    if not script.exists():
        raise FileNotFoundError(f"原脚本未找到: {script}")
    
    cmd = ["bash", str(script), "-i", str(case_dir)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    
    if result.returncode != 0:
        print(f"原脚本执行失败: {result.stderr}", file=sys.stderr)
        return MatchResult("")
    
    return MatchResult(result.stdout)


def run_new_implementation(case_dir: Path) -> MatchResult:
    """运行新的 Python 实现"""
    cmd = ["python", "-m", "capmaster", "match", "-i", str(case_dir)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    
    if result.returncode != 0:
        print(f"新实现执行失败: {result.stderr}", file=sys.stderr)
        return MatchResult("")
    
    return MatchResult(result.stdout)


def compare_results(old: MatchResult, new: MatchResult, case_name: str) -> Dict:
    """对比两个结果"""
    comparison = {
        "case": case_name,
        "old_matched": old.matched_count,
        "new_matched": new.matched_count,
        "old_total": old.total_connections,
        "new_total": new.total_connections,
        "match_diff": new.matched_count - old.matched_count,
        "exact_matches": 0,
        "score_diffs": [],
        "only_in_old": [],
        "only_in_new": [],
    }
    
    # 创建匹配对的集合（忽略分数）
    old_pairs = {(s1, s2) for s1, s2, _ in old.matches}
    new_pairs = {(s1, s2) for s1, s2, _ in new.matches}
    
    # 统计完全相同的匹配
    comparison["exact_matches"] = len(old_pairs & new_pairs)
    
    # 统计仅在旧版本中的匹配
    comparison["only_in_old"] = list(old_pairs - new_pairs)
    
    # 统计仅在新版本中的匹配
    comparison["only_in_new"] = list(new_pairs - old_pairs)
    
    # 对于相同的匹配对，比较分数差异
    old_scores = {(s1, s2): score for s1, s2, score in old.matches}
    new_scores = {(s1, s2): score for s1, s2, score in new.matches}
    
    for pair in old_pairs & new_pairs:
        old_score = old_scores[pair]
        new_score = new_scores[pair]
        if old_score != new_score:
            comparison["score_diffs"].append({
                "pair": pair,
                "old_score": old_score,
                "new_score": new_score,
                "diff": new_score - old_score
            })
    
    return comparison


def print_comparison(comp: Dict):
    """打印对比结果"""
    print(f"\n{'='*80}")
    print(f"案例: {comp['case']}")
    print(f"{'='*80}")
    
    print(f"\n总连接数:")
    print(f"  原脚本: File1={comp['old_total'][0]}, File2={comp['old_total'][1]}")
    print(f"  新实现: File1={comp['new_total'][0]}, File2={comp['new_total'][1]}")
    
    print(f"\n匹配数量:")
    print(f"  原脚本: {comp['old_matched']} 对")
    print(f"  新实现: {comp['new_matched']} 对")
    print(f"  差异: {comp['match_diff']:+d} 对")
    
    print(f"\n匹配对比:")
    print(f"  完全相同的匹配: {comp['exact_matches']} 对")
    print(f"  仅在原脚本中: {len(comp['only_in_old'])} 对")
    print(f"  仅在新实现中: {len(comp['only_in_new'])} 对")
    
    if comp['score_diffs']:
        print(f"\n分数差异 ({len(comp['score_diffs'])} 对):")
        for diff in comp['score_diffs'][:5]:  # 只显示前5个
            print(f"  {diff['pair']}: {diff['old_score']} -> {diff['new_score']} ({diff['diff']:+d})")
        if len(comp['score_diffs']) > 5:
            print(f"  ... 还有 {len(comp['score_diffs']) - 5} 对")
    
    if comp['only_in_old']:
        print(f"\n仅在原脚本中的匹配 (前5对):")
        for pair in comp['only_in_old'][:5]:
            print(f"  {pair}")
        if len(comp['only_in_old']) > 5:
            print(f"  ... 还有 {len(comp['only_in_old']) - 5} 对")
    
    if comp['only_in_new']:
        print(f"\n仅在新实现中的匹配 (前5对):")
        for pair in comp['only_in_new'][:5]:
            print(f"  {pair}")
        if len(comp['only_in_new']) > 5:
            print(f"  ... 还有 {len(comp['only_in_new']) - 5} 对")


def test_case(case_dir: Path) -> Dict:
    """测试单个案例"""
    print(f"\n测试案例: {case_dir.name}")
    print(f"运行原脚本...")
    old_result = run_old_script(case_dir)
    
    print(f"运行新实现...")
    new_result = run_new_implementation(case_dir)
    
    comparison = compare_results(old_result, new_result, case_dir.name)
    print_comparison(comparison)
    
    return comparison


def find_dual_file_cases() -> List[Path]:
    """查找所有包含2个pcap文件的案例"""
    cases_dir = Path("cases")
    dual_cases = []
    
    for case_dir in cases_dir.iterdir():
        if not case_dir.is_dir():
            continue
        
        pcap_files = list(case_dir.glob("*.pcap")) + list(case_dir.glob("*.pcapng"))
        if len(pcap_files) == 2:
            dual_cases.append(case_dir)
    
    return sorted(dual_cases)


def main():
    if len(sys.argv) < 2:
        print("用法: python scripts/compare_match.py <case_dir>")
        print("      python scripts/compare_match.py --all")
        sys.exit(1)
    
    if sys.argv[1] == "--all":
        # 测试所有双文件案例
        cases = find_dual_file_cases()
        print(f"找到 {len(cases)} 个双文件案例")
        
        all_comparisons = []
        for case_dir in cases:
            try:
                comp = test_case(case_dir)
                all_comparisons.append(comp)
            except Exception as e:
                print(f"测试失败: {case_dir.name}: {e}", file=sys.stderr)
        
        # 打印汇总
        print(f"\n{'='*80}")
        print("汇总统计")
        print(f"{'='*80}")
        
        total_cases = len(all_comparisons)
        exact_match_cases = sum(1 for c in all_comparisons if c['match_diff'] == 0)
        
        print(f"\n总案例数: {total_cases}")
        print(f"匹配数完全相同: {exact_match_cases} ({exact_match_cases/total_cases*100:.1f}%)")
        print(f"匹配数不同: {total_cases - exact_match_cases}")
        
        # 保存详细结果到JSON
        output_file = Path("match_comparison_results.json")
        with open(output_file, "w") as f:
            json.dump(all_comparisons, f, indent=2)
        print(f"\n详细结果已保存到: {output_file}")
        
    else:
        # 测试单个案例
        case_dir = Path(sys.argv[1])
        if not case_dir.exists():
            print(f"案例目录不存在: {case_dir}", file=sys.stderr)
            sys.exit(1)
        
        test_case(case_dir)


if __name__ == "__main__":
    main()

