#!/usr/bin/env python3
"""创建 kase_133_tcp_stream_extra 表（基于 kase_134_tcp_stream_extra 的结构）"""

import sys
import psycopg2
from psycopg2 import OperationalError

# Database connection parameters
DB_CONFIG = {
    'host': '172.16.200.156',
    'port': 5433,
    'database': 'r2',
    'user': 'postgres',
    'password': 'password'
}

def create_table():
    """创建 kase_133_tcp_stream_extra 表"""
    
    print("=" * 100)
    print("创建 public.kase_133_tcp_stream_extra 表")
    print("=" * 100)
    print(f"\n数据库: {DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}")
    print(f"基于表: public.kase_134_tcp_stream_extra\n")
    
    try:
        # 连接数据库
        conn = psycopg2.connect(
            host=DB_CONFIG['host'],
            port=DB_CONFIG['port'],
            database=DB_CONFIG['database'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            connect_timeout=10
        )
        
        # 关闭自动提交，使用事务
        conn.autocommit = False
        cursor = conn.cursor()
        
        # Step 1: 检查表是否已存在
        print("Step 1: 检查表是否已存在...")
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'kase_133_tcp_stream_extra'
            );
        """)
        
        if cursor.fetchone()[0]:
            print("⚠️  表 kase_133_tcp_stream_extra 已存在！")
            print("\n操作终止。如需重建，请先手动删除该表。")
            cursor.close()
            conn.close()
            return False
        
        print("✅ 表不存在，可以创建")
        
        # Step 2: 获取源表结构
        print("\nStep 2: 获取源表 kase_134_tcp_stream_extra 的结构...")
        cursor.execute("""
            SELECT 
                column_name,
                data_type,
                character_maximum_length,
                is_nullable,
                column_default,
                udt_name
            FROM information_schema.columns
            WHERE table_schema = 'public' 
              AND table_name = 'kase_134_tcp_stream_extra'
            ORDER BY ordinal_position;
        """)
        
        columns = cursor.fetchall()
        
        if not columns:
            print("❌ 源表 kase_134_tcp_stream_extra 不存在或无列！")
            cursor.close()
            conn.close()
            return False
        
        print(f"✅ 获取到 {len(columns)} 个列定义")
        
        # Step 3: 构建 CREATE TABLE 语句
        print("\nStep 3: 构建 CREATE TABLE 语句...")
        
        col_definitions = []
        for col_name, data_type, max_len, nullable, default, udt_name in columns:
            col_def = f"    {col_name} "

            # 处理数据类型
            if data_type == 'ARRAY':
                # 处理数组类型 - 去掉下划线前缀
                base_type = udt_name
                if base_type.startswith('_'):
                    base_type = base_type[1:]  # 去掉下划线
                col_def += f"{base_type}[]"
            elif max_len:
                col_def += f"{data_type}({max_len})"
            else:
                col_def += data_type

            # 处理 NULL/NOT NULL
            if nullable == 'NO':
                col_def += " NOT NULL"

            # 处理默认值 - 需要替换序列名
            if default:
                # 将 kase_134 替换为 kase_133
                new_default = default.replace('kase_134', 'kase_133')
                col_def += f" DEFAULT {new_default}"

            col_definitions.append(col_def)
        
        create_sql = "CREATE TABLE public.kase_133_tcp_stream_extra (\n"
        create_sql += ",\n".join(col_definitions)
        create_sql += "\n);"
        
        print("\n生成的 SQL 语句：")
        print("-" * 100)
        print(create_sql)
        print("-" * 100)
        
        # Step 4: 创建序列（如果需要）
        print("\nStep 4: 检查并创建序列...")
        
        # 检查是否需要创建序列
        need_sequence = any('nextval' in str(col[4]) for col in columns if col[4])
        
        if need_sequence:
            sequence_name = 'kase_133_tcp_stream_extra_id_seq'
            
            # 检查序列是否已存在
            cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM pg_class 
                    WHERE relkind = 'S' 
                    AND relname = %s
                );
            """, (sequence_name,))
            
            if not cursor.fetchone()[0]:
                cursor.execute(f"CREATE SEQUENCE public.{sequence_name};")
                print(f"✅ 创建序列: {sequence_name}")
            else:
                print(f"⚠️  序列已存在: {sequence_name}")
        else:
            print("ℹ️  不需要创建序列")
        
        # Step 5: 执行 CREATE TABLE
        print("\nStep 5: 执行 CREATE TABLE...")
        cursor.execute(create_sql)
        print("✅ 表创建成功")
        
        # Step 6: 创建索引（基于最佳实践）
        print("\nStep 6: 创建索引...")
        
        indexes = [
            ("idx_kase_133_tcp_stream_extra_pcap_id", "pcap_id"),
            ("idx_kase_133_tcp_stream_extra_flow_hash", "flow_hash"),
            ("idx_kase_133_tcp_stream_extra_time", "first_time, last_time"),
        ]
        
        for idx_name, idx_columns in indexes:
            cursor.execute(f"""
                CREATE INDEX {idx_name} 
                ON public.kase_133_tcp_stream_extra({idx_columns});
            """)
            print(f"  ✅ 创建索引: {idx_name}")
        
        # Step 7: 添加主键约束（如果有 id 列）
        print("\nStep 7: 添加主键约束...")
        
        # 检查是否有 id 列
        has_id_column = any(col[0] == 'id' for col in columns)
        
        if has_id_column:
            cursor.execute("""
                ALTER TABLE public.kase_133_tcp_stream_extra 
                ADD CONSTRAINT kase_133_tcp_stream_extra_pkey PRIMARY KEY (id);
            """)
            print("  ✅ 添加主键约束: kase_133_tcp_stream_extra_pkey")
        else:
            print("  ℹ️  无 id 列，跳过主键约束")
        
        # Step 8: 添加表注释
        print("\nStep 8: 添加表注释...")
        cursor.execute("""
            COMMENT ON TABLE public.kase_133_tcp_stream_extra IS 
            'TCP stream extra information for kase 133 (created based on kase_134_tcp_stream_extra structure)';
        """)
        print("  ✅ 添加表注释")
        
        # Step 9: 验证表结构
        print("\nStep 9: 验证新表结构...")
        cursor.execute("""
            SELECT 
                column_name,
                data_type,
                is_nullable,
                column_default
            FROM information_schema.columns
            WHERE table_schema = 'public' 
              AND table_name = 'kase_133_tcp_stream_extra'
            ORDER BY ordinal_position;
        """)
        
        new_columns = cursor.fetchall()
        print(f"\n新表结构（共 {len(new_columns)} 列）：")
        print(f"{'列名':<30} {'数据类型':<20} {'可空':<10} {'默认值':<30}")
        print("-" * 100)
        for col_name, data_type, nullable, default in new_columns:
            default_str = str(default)[:30] if default else ""
            print(f"{col_name:<30} {data_type:<20} {nullable:<10} {default_str:<30}")
        
        # Step 10: 验证索引
        print("\n验证索引：")
        cursor.execute("""
            SELECT indexname 
            FROM pg_indexes
            WHERE schemaname = 'public' 
              AND tablename = 'kase_133_tcp_stream_extra'
            ORDER BY indexname;
        """)
        
        indexes_created = cursor.fetchall()
        for (idx_name,) in indexes_created:
            print(f"  ✅ {idx_name}")
        
        # Step 11: 提交事务
        print("\n" + "=" * 100)
        print("准备提交事务...")
        print("=" * 100)
        
        conn.commit()
        print("\n✅✅✅ 表创建成功并已提交！✅✅✅")
        
        # 显示最终摘要
        print("\n" + "=" * 100)
        print("创建摘要")
        print("=" * 100)
        print(f"✅ 表名: public.kase_133_tcp_stream_extra")
        print(f"✅ 列数: {len(new_columns)}")
        print(f"✅ 索引数: {len(indexes_created)}")
        print(f"✅ 主键: {'是' if has_id_column else '否'}")
        print(f"✅ 当前行数: 0 (新表)")
        print("=" * 100)
        
        cursor.close()
        conn.close()
        return True
        
    except OperationalError as e:
        print(f"\n❌ 数据库连接失败！")
        print(f"错误: {str(e)}")
        return False
        
    except Exception as e:
        print(f"\n❌ 创建表时发生错误！")
        print(f"错误类型: {type(e).__name__}")
        print(f"错误信息: {str(e)}")
        
        # 回滚事务
        if 'conn' in locals():
            conn.rollback()
            print("\n⚠️  事务已回滚，数据库未被修改")
            conn.close()
        
        return False

if __name__ == "__main__":
    print("\n⚠️  警告：此操作将在数据库中创建新表！\n")
    
    response = input("确认继续？(yes/no): ")
    
    if response.lower() == 'yes':
        success = create_table()
        sys.exit(0 if success else 1)
    else:
        print("\n操作已取消")
        sys.exit(0)

