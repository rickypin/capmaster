#!/usr/bin/env python3
"""Analyze behavioral matching results and provide insights for tuning."""
from __future__ import annotations

import csv
import sys
from pathlib import Path
from typing import Any

def load_summary(csv_path: Path) -> list[dict[str, Any]]:
    """Load summary CSV and parse numeric fields."""
    rows = []
    with csv_path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Parse numeric fields
            for key in ["rc_auto", "rc_beh"]:
                row[key] = int(row[key]) if row[key] else None
            for key in ["auto_total1", "auto_total2", "auto_matched", "beh_total1", "beh_total2", "beh_matched"]:
                row[key] = int(row[key]) if row[key] else None
            for key in ["auto_rate1(%)", "auto_rate2(%)", "auto_avg", "beh_rate1(%)", "beh_rate2(%)", "beh_avg"]:
                row[key] = float(row[key]) if row[key] else None
            for key in ["delta_matched(beh-auto)", "delta_avg(beh-auto)"]:
                row[key] = float(row[key]) if row[key] else None
            rows.append(row)
    return rows

def analyze(rows: list[dict[str, Any]]) -> None:
    """Analyze and print insights."""
    print("=" * 80)
    print("行为匹配策略效果分析")
    print("=" * 80)
    print()
    
    # Filter successful cases
    valid = [r for r in rows if r["rc_auto"] == 0 and r["rc_beh"] == 0]
    print(f"总用例数: {len(rows)}")
    print(f"成功运行: {len(valid)}")
    print()
    
    if not valid:
        print("无有效数据")
        return
    
    # Category 1: Behavioral finds more matches
    more_matches = [r for r in valid if (r["delta_matched(beh-auto)"] or 0) > 0]
    # Category 2: Behavioral finds fewer matches
    fewer_matches = [r for r in valid if (r["delta_matched(beh-auto)"] or 0) < 0]
    # Category 3: Same number of matches
    same_matches = [r for r in valid if (r["delta_matched(beh-auto)"] or 0) == 0]
    
    print("## 1. 匹配对数对比")
    print(f"  行为策略匹配更多: {len(more_matches)} 个用例")
    print(f"  行为策略匹配更少: {len(fewer_matches)} 个用例")
    print(f"  匹配数相同:       {len(same_matches)} 个用例")
    print()
    
    if more_matches:
        print("  行为策略匹配更多的用例（前10）:")
        for r in sorted(more_matches, key=lambda x: x["delta_matched(beh-auto)"], reverse=True)[:10]:
            delta = r["delta_matched(beh-auto)"]
            auto_m = r["auto_matched"]
            beh_m = r["beh_matched"]
            print(f"    {r['case']:30s}  auto={auto_m:4d}  beh={beh_m:4d}  delta=+{delta:.0f}")
        print()
    
    if fewer_matches:
        print("  行为策略匹配更少的用例（前10）:")
        for r in sorted(fewer_matches, key=lambda x: x["delta_matched(beh-auto)"])[:10]:
            delta = r["delta_matched(beh-auto)"]
            auto_m = r["auto_matched"]
            beh_m = r["beh_matched"]
            print(f"    {r['case']:30s}  auto={auto_m:4d}  beh={beh_m:4d}  delta={delta:.0f}")
        print()
    
    # Average score comparison
    print("## 2. 平均分数对比")
    avg_delta = sum(r["delta_avg(beh-auto)"] or 0 for r in valid) / len(valid)
    print(f"  平均分数差异（beh - auto）: {avg_delta:+.3f}")
    
    higher_score = [r for r in valid if (r["delta_avg(beh-auto)"] or 0) > 0]
    lower_score = [r for r in valid if (r["delta_avg(beh-auto)"] or 0) < 0]
    print(f"  行为策略分数更高: {len(higher_score)} 个用例")
    print(f"  行为策略分数更低: {len(lower_score)} 个用例")
    print()
    
    # Match rate comparison
    print("## 3. 匹配率对比（file 1）")
    auto_rates = [r["auto_rate1(%)"] for r in valid if r["auto_rate1(%)"] is not None]
    beh_rates = [r["beh_rate1(%)"] for r in valid if r["beh_rate1(%)"] is not None]
    if auto_rates and beh_rates:
        print(f"  auto 平均匹配率: {sum(auto_rates)/len(auto_rates):.1f}%")
        print(f"  beh  平均匹配率: {sum(beh_rates)/len(beh_rates):.1f}%")
        print(f"  差异: {sum(beh_rates)/len(beh_rates) - sum(auto_rates)/len(auto_rates):+.1f}%")
    print()
    
    # Detailed case-by-case
    print("## 4. 详细用例列表")
    print(f"{'用例':30s} {'auto匹配':>10s} {'beh匹配':>10s} {'delta':>8s} {'auto分数':>10s} {'beh分数':>10s} {'delta分数':>10s}")
    print("-" * 100)
    for r in valid:
        auto_m = r["auto_matched"] or 0
        beh_m = r["beh_matched"] or 0
        delta_m = r["delta_matched(beh-auto)"] or 0
        auto_s = r["auto_avg"] or 0.0
        beh_s = r["beh_avg"] or 0.0
        delta_s = r["delta_avg(beh-auto)"] or 0.0
        print(f"{r['case']:30s} {auto_m:10d} {beh_m:10d} {delta_m:+8.0f} {auto_s:10.2f} {beh_s:10.2f} {delta_s:+10.2f}")
    print()
    
    print("=" * 80)
    print("调优建议")
    print("=" * 80)
    print()
    print("基于以上分析，可以考虑以下调优方向：")
    print()
    print("1. 如果行为策略匹配数显著增加但分数偏低：")
    print("   - 可能引入了较多低质量匹配")
    print("   - 建议：提高阈值（当前0.60）或调整权重")
    print()
    print("2. 如果行为策略在某些用例表现差：")
    print("   - 检查这些用例的特点（连接时长、报文间隔、字节数分布）")
    print("   - 建议：针对性调整特征权重或增加新特征")
    print()
    print("3. 如果行为策略普遍优于原策略：")
    print("   - 可以考虑将行为特征融入 auto 模式")
    print("   - 建议：作为额外评分维度或在特定场景下优先使用")
    print()

def main() -> int:
    csv_path = Path("eval_results/2hops/summary.csv")
    if not csv_path.exists():
        print(f"Error: {csv_path} not found", file=sys.stderr)
        return 1
    
    rows = load_summary(csv_path)
    analyze(rows)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

