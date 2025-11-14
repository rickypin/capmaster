#!/usr/bin/env python3
"""Summarize validation results from log file."""
import re
import sys

log_file = "eval_results/validation/full_validation.log"

# Parse log file
results = []
with open(log_file) as f:
    for line in f:
        match = re.search(r'\[(\d+)/\d+\] ([\w\-_.]+)\.\.\. ✓ auto=(\d+), behavioral=(\d+)', line)
        if match:
            idx, case, auto, behav = match.groups()
            results.append({
                'case': case,
                'auto': int(auto),
                'behavioral': int(behav),
                'delta': int(behav) - int(auto),
            })

if not results:
    print("No results found in log file")
    sys.exit(1)

# Calculate statistics
total_auto = sum(r['auto'] for r in results)
total_behav = sum(r['behavioral'] for r in results)
total_delta = total_behav - total_auto

behav_wins = sum(1 for r in results if r['behavioral'] > r['auto'])
auto_wins = sum(1 for r in results if r['auto'] > r['behavioral'])
ties = sum(1 for r in results if r['auto'] == r['behavioral'])

# Print summary
print("=" * 100)
print(f"验证结果总结 - 基于 {len(results)} 个用例")
print("=" * 100)
print()
print(f"总匹配数:")
print(f"  Auto 模式:           {total_auto:6d}")
print(f"  Behavioral (推荐):   {total_behav:6d}")
print(f"  差值:                {total_delta:+6d} ({100*total_delta/total_auto if total_auto > 0 else 0:+.1f}%)")
print()
print(f"用例对比:")
print(f"  Behavioral 更优:     {behav_wins:3d} ({100*behav_wins/len(results):.1f}%)")
print(f"  Auto 更优:           {auto_wins:3d} ({100*auto_wins/len(results):.1f}%)")
print(f"  持平:                {ties:3d} ({100*ties/len(results):.1f}%)")
print()

# Top improvements
improvements = sorted(results, key=lambda x: x['delta'], reverse=True)
print("Top 10 提升最大的用例 (behavioral - auto):")
for i, r in enumerate(improvements[:10], 1):
    print(f"  {i:2d}. {r['case']:35s} {r['delta']:+6d}  (auto={r['auto']}, behav={r['behavioral']})")
print()

# Top regressions
print("Top 10 下降最大的用例 (behavioral - auto):")
for i, r in enumerate(reversed(improvements[-10:]), 1):
    print(f"  {i:2d}. {r['case']:35s} {r['delta']:+6d}  (auto={r['auto']}, behav={r['behavioral']})")
print()

# Recommendation
print("=" * 100)
print("结论")
print("=" * 100)
if total_delta > total_auto * 0.1:
    print("✓ 推荐配置显著优于 auto 模式（匹配数提升 >10%）")
    print("  建议：将推荐配置（overlap=0%, duration=40%, iat=30%, bytes=30%）设为 behavioral 模式的默认配置")
elif total_delta > 0:
    print("✓ 推荐配置略优于 auto 模式")
    print("  建议：可作为 behavioral 模式的默认配置")
else:
    print("⚠️  推荐配置未显著优于 auto 模式")
    print("  建议：需要进一步调优或针对特定场景使用")
print()

