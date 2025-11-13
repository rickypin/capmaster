#!/usr/bin/env python3
"""
演示 Python GIL 对多线程性能的影响

这个脚本展示了为什么在 match 插件中使用多线程并行化不是一个好主意。
"""

import time
import threading
from multiprocessing import Pool, cpu_count


def cpu_intensive_task(n: int) -> int:
    """
    模拟 CPU 密集型任务（类似于连接匹配中的评分计算）
    
    Args:
        n: 计算次数
        
    Returns:
        计算结果
    """
    total = 0
    for i in range(n):
        # 模拟复杂的评分计算
        total += i ** 2
        total = total % 1000000
    return total


def benchmark_single_thread(iterations: int, task_count: int = 2):
    """单线程基准测试"""
    print(f"\n{'='*60}")
    print(f"单线程执行 {task_count} 个任务")
    print(f"{'='*60}")
    
    start = time.time()
    results = []
    for i in range(task_count):
        result = cpu_intensive_task(iterations)
        results.append(result)
    elapsed = time.time() - start
    
    print(f"执行时间: {elapsed:.3f} 秒")
    print(f"平均每任务: {elapsed/task_count:.3f} 秒")
    
    return elapsed


def benchmark_multi_thread(iterations: int, task_count: int = 2):
    """多线程基准测试"""
    print(f"\n{'='*60}")
    print(f"多线程执行 {task_count} 个任务（{task_count} 个线程）")
    print(f"{'='*60}")
    
    start = time.time()
    threads = []
    results = []
    
    def worker(n):
        result = cpu_intensive_task(n)
        results.append(result)
    
    for i in range(task_count):
        t = threading.Thread(target=worker, args=(iterations,))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    elapsed = time.time() - start
    
    print(f"执行时间: {elapsed:.3f} 秒")
    print(f"平均每任务: {elapsed/task_count:.3f} 秒")
    print(f"⚠️  注意：由于 GIL，多线程时间 ≈ 单线程时间")
    
    return elapsed


def benchmark_multi_process(iterations: int, task_count: int = 2):
    """多进程基准测试"""
    print(f"\n{'='*60}")
    print(f"多进程执行 {task_count} 个任务（{task_count} 个进程）")
    print(f"{'='*60}")
    
    start = time.time()
    
    with Pool(processes=task_count) as pool:
        results = pool.map(cpu_intensive_task, [iterations] * task_count)
    
    elapsed = time.time() - start
    
    print(f"执行时间: {elapsed:.3f} 秒")
    print(f"平均每任务: {elapsed/task_count:.3f} 秒")
    print(f"✅ 多进程可以真正并行，但有进程创建和 IPC 开销")
    
    return elapsed


def main():
    """主函数"""
    print("="*60)
    print("Python GIL 影响演示")
    print("="*60)
    print(f"CPU 核心数: {cpu_count()}")
    
    # 调整这个值来控制任务的计算量
    # 值越大，任务越耗时
    iterations = 10_000_000
    task_count = 4
    
    print(f"\n每个任务执行 {iterations:,} 次计算")
    print(f"总共 {task_count} 个任务")
    
    # 运行基准测试
    single_time = benchmark_single_thread(iterations, task_count)
    multi_thread_time = benchmark_multi_thread(iterations, task_count)
    multi_process_time = benchmark_multi_process(iterations, task_count)
    
    # 性能对比
    print(f"\n{'='*60}")
    print("性能对比总结")
    print(f"{'='*60}")
    print(f"单线程时间:   {single_time:.3f} 秒 (基准)")
    print(f"多线程时间:   {multi_thread_time:.3f} 秒 (加速比: {single_time/multi_thread_time:.2f}x)")
    print(f"多进程时间:   {multi_process_time:.3f} 秒 (加速比: {single_time/multi_process_time:.2f}x)")
    
    print(f"\n{'='*60}")
    print("结论")
    print(f"{'='*60}")
    print("1. 多线程几乎没有加速（甚至可能更慢），因为 GIL 限制")
    print("2. 多进程可以加速，但有额外开销（进程创建、IPC）")
    print("3. 对于 match 插件：")
    print("   - 数据量大，IPC 序列化开销会抵消多进程收益")
    print("   - 优化算法和内存使用比并行化更有效")
    print("="*60)


if __name__ == "__main__":
    main()

