#!/usr/bin/env python3
"""
批量比较 PCAP 文件示例脚本
使用 --quiet 模式减少屏幕输出
"""

import subprocess
import sys
import time
from pathlib import Path
from typing import List, Tuple


class ComparisonTask:
    """单个比较任务"""
    
    def __init__(
        self,
        file1: str,
        pcapid1: int,
        file2: str,
        pcapid2: int,
        description: str = "",
    ):
        self.file1 = Path(file1)
        self.pcapid1 = pcapid1
        self.file2 = Path(file2)
        self.pcapid2 = pcapid2
        self.description = description or f"{file1} vs {file2}"
    
    def validate(self) -> Tuple[bool, str]:
        """验证文件是否存在"""
        if not self.file1.exists():
            return False, f"Baseline file not found: {self.file1}"
        if not self.file2.exists():
            return False, f"Compare file not found: {self.file2}"
        return True, ""


class BatchComparer:
    """批量比较器"""
    
    def __init__(
        self,
        output_dir: str = "./comparison_results",
        db_connection: str | None = None,
        kase_id: int | None = None,
        log_file: str = "./batch_compare.log",
    ):
        self.output_dir = Path(output_dir)
        self.db_connection = db_connection
        self.kase_id = kase_id
        self.log_file = Path(log_file)
        
        # 创建输出目录
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # 清空日志文件
        self.log_file.write_text("")
        
        # 统计
        self.total = 0
        self.success = 0
        self.failed = 0
    
    def log(self, message: str, to_console: bool = True):
        """记录日志"""
        if to_console:
            print(message)
        with open(self.log_file, "a") as f:
            f.write(message + "\n")
    
    def run_comparison(self, task: ComparisonTask, task_num: int) -> bool:
        """运行单个比较任务"""
        self.log(f"[{task_num}/{self.total}] Processing: {task.description}")
        self.log(f"  Baseline: {task.file1.name} (pcap_id={task.pcapid1})")
        self.log(f"  Compare:  {task.file2.name} (pcap_id={task.pcapid2})")
        
        # 验证文件
        valid, error_msg = task.validate()
        if not valid:
            self.log(f"  ❌ ERROR: {error_msg}")
            self.failed += 1
            self.log("")
            return False
        
        # 生成输出文件名
        output_file = self.output_dir / (
            f"result_{task_num}_"
            f"{task.file1.stem}_vs_{task.file2.stem}.txt"
        )
        
        # 构建命令
        cmd = [
            "capmaster", "compare",
            "--file1", str(task.file1),
            "--file1-pcapid", str(task.pcapid1),
            "--file2", str(task.file2),
            "--file2-pcapid", str(task.pcapid2),
            "--quiet",
            "-o", str(output_file),
        ]
        
        # 添加数据库参数
        if self.db_connection and self.kase_id is not None:
            cmd.extend([
                "--show-flow-hash",
                "--db-connection", self.db_connection,
                "--kase-id", str(self.kase_id),
            ])
        
        # 执行比较
        start_time = time.time()
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
            )
            
            duration = time.time() - start_time
            
            # 检查输出文件
            if output_file.exists():
                file_size = output_file.stat().st_size
                self.log(
                    f"  ✅ SUCCESS ({duration:.1f}s, {file_size:,} bytes)"
                )
                self.log(f"  Output: {output_file}")
                self.success += 1
                
                # 记录详细日志
                if result.stderr:
                    with open(self.log_file, "a") as f:
                        f.write("  --- Detailed logs ---\n")
                        f.write(result.stderr)
                        f.write("  --- End of logs ---\n")
                
                return True
            else:
                self.log("  ⚠️  WARNING: Completed but output file not found")
                self.failed += 1
                return False
                
        except subprocess.CalledProcessError as e:
            duration = time.time() - start_time
            self.log(f"  ❌ FAILED ({duration:.1f}s)")
            self.log(f"  Error: {e}")
            
            # 记录错误详情
            with open(self.log_file, "a") as f:
                f.write("  --- Error details ---\n")
                if e.stdout:
                    f.write("  STDOUT:\n")
                    f.write(e.stdout)
                if e.stderr:
                    f.write("  STDERR:\n")
                    f.write(e.stderr)
                f.write("  --- End of error details ---\n")
            
            self.failed += 1
            return False
        
        finally:
            self.log("")
    
    def run_batch(self, tasks: List[ComparisonTask]) -> int:
        """运行批量比较"""
        self.total = len(tasks)
        
        # 打印头部
        self.log("=" * 80)
        self.log("Batch PCAP Comparison - Quiet Mode")
        self.log("=" * 80)
        self.log(f"Total pairs to process: {self.total}")
        self.log(f"Output directory: {self.output_dir}")
        if self.db_connection:
            self.log(f"Database: {self.db_connection}")
            self.log(f"Case ID: {self.kase_id}")
        self.log("=" * 80)
        self.log("")
        
        # 处理每个任务
        for i, task in enumerate(tasks, 1):
            self.run_comparison(task, i)
        
        # 打印总结
        self.log("=" * 80)
        self.log("Batch Processing Summary")
        self.log("=" * 80)
        self.log(f"Total:   {self.total}")
        self.log(f"Success: {self.success}")
        self.log(f"Failed:  {self.failed}")
        self.log("=" * 80)
        
        # 列出生成的文件
        if self.success > 0:
            self.log("")
            self.log("Generated files:")
            for output_file in sorted(self.output_dir.glob("*.txt")):
                size = output_file.stat().st_size
                self.log(f"  {output_file.name} ({size:,} bytes)")
        
        # 返回退出码
        if self.failed > 0:
            self.log("")
            self.log(f"⚠️  Some comparisons failed. Check {self.log_file} for details.")
            return 1
        else:
            self.log("")
            self.log("✅ All comparisons completed successfully!")
            return 0


def main():
    """主函数"""
    
    # 配置
    DB_CONNECTION = "postgresql://postgres:password@172.16.200.156:5433/r2"
    KASE_ID = 133
    OUTPUT_DIR = "./comparison_results"
    LOG_FILE = "./batch_compare.log"
    
    # 定义要比较的文件对
    tasks = [
        ComparisonTask(
            "baseline_v1.pcap", 0,
            "test_v1.pcap", 1,
            "Version 1 Comparison"
        ),
        ComparisonTask(
            "baseline_v2.pcap", 0,
            "test_v2.pcap", 1,
            "Version 2 Comparison"
        ),
        ComparisonTask(
            "baseline_v3.pcap", 0,
            "test_v3.pcap", 1,
            "Version 3 Comparison"
        ),
    ]
    
    # 创建批量比较器
    comparer = BatchComparer(
        output_dir=OUTPUT_DIR,
        db_connection=DB_CONNECTION,
        kase_id=KASE_ID,
        log_file=LOG_FILE,
    )
    
    # 运行批量比较
    exit_code = comparer.run_batch(tasks)
    
    return exit_code


if __name__ == "__main__":
    sys.exit(main())

