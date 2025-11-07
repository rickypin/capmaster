#!/usr/bin/env python3
"""验证 kase_133_tcp_stream_extra 表创建结果"""

import psycopg2

DB_CONFIG = {
    'host': '172.16.200.156',
    'port': 5433,
    'database': 'r2',
    'user': 'postgres',
    'password': 'password'
}

def verify_table():
    """验证新表与源表的结构对比"""
    
    print("=" * 100)
    print("验证 kase_133_tcp_stream_extra 表创建结果")
    print("=" * 100)
    
    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()
    
    # 1. 对比两个表的列结构
    print("\n📋 列结构对比：")
    print("-" * 100)
    
    for table_name in ['kase_134_tcp_stream_extra', 'kase_133_tcp_stream_extra']:
        cursor.execute("""
            SELECT 
                column_name,
                data_type,
                is_nullable,
                column_default
            FROM information_schema.columns
            WHERE table_schema = 'public' 
              AND table_name = %s
            ORDER BY ordinal_position;
        """, (table_name,))
        
        columns = cursor.fetchall()
        print(f"\n{table_name} ({len(columns)} 列):")
        print(f"  {'列名':<30} {'类型':<15} {'可空':<8} {'默认值':<30}")
        print("  " + "-" * 90)
        for col_name, data_type, nullable, default in columns:
            default_str = str(default)[:30] if default else ""
            print(f"  {col_name:<30} {data_type:<15} {nullable:<8} {default_str:<30}")
    
    # 2. 对比索引
    print("\n\n🔑 索引对比：")
    print("-" * 100)
    
    for table_name in ['kase_134_tcp_stream_extra', 'kase_133_tcp_stream_extra']:
        cursor.execute("""
            SELECT indexname, indexdef
            FROM pg_indexes
            WHERE schemaname = 'public' 
              AND tablename = %s
            ORDER BY indexname;
        """, (table_name,))
        
        indexes = cursor.fetchall()
        print(f"\n{table_name} ({len(indexes)} 个索引):")
        for idx_name, idx_def in indexes:
            print(f"  ✅ {idx_name}")
    
    # 3. 对比约束
    print("\n\n🔒 约束对比：")
    print("-" * 100)
    
    for table_name in ['kase_134_tcp_stream_extra', 'kase_133_tcp_stream_extra']:
        cursor.execute("""
            SELECT
                conname,
                contype,
                pg_get_constraintdef(oid) as definition
            FROM pg_constraint
            WHERE conrelid = ('public.' || %s)::regclass
            ORDER BY conname;
        """, (table_name,))
        
        constraints = cursor.fetchall()
        print(f"\n{table_name} ({len(constraints)} 个约束):")
        if constraints:
            for con_name, con_type, con_def in constraints:
                type_map = {'p': 'PRIMARY KEY', 'f': 'FOREIGN KEY', 'u': 'UNIQUE', 'c': 'CHECK'}
                con_type_str = type_map.get(con_type, con_type)
                print(f"  ✅ {con_name} ({con_type_str})")
        else:
            print("  ⚠️  无约束")
    
    # 4. 检查数据行数
    print("\n\n📊 数据行数：")
    print("-" * 100)
    
    for table_name in ['kase_134_tcp_stream_extra', 'kase_133_tcp_stream_extra']:
        cursor.execute(f"SELECT COUNT(*) FROM public.{table_name};")
        count = cursor.fetchone()[0]
        print(f"  {table_name:<40}: {count} 行")
    
    # 5. 检查表大小
    print("\n\n💾 表大小：")
    print("-" * 100)
    
    for table_name in ['kase_134_tcp_stream_extra', 'kase_133_tcp_stream_extra']:
        cursor.execute(f"""
            SELECT pg_size_pretty(pg_total_relation_size('public.{table_name}'));
        """)
        size = cursor.fetchone()[0]
        print(f"  {table_name:<40}: {size}")
    
    # 6. 最终验证
    print("\n\n" + "=" * 100)
    print("✅ 验证完成")
    print("=" * 100)
    
    # 检查结构是否一致
    cursor.execute("""
        SELECT column_name, data_type, is_nullable
        FROM information_schema.columns
        WHERE table_schema = 'public' 
          AND table_name = 'kase_134_tcp_stream_extra'
        ORDER BY ordinal_position;
    """)
    cols_134 = cursor.fetchall()
    
    cursor.execute("""
        SELECT column_name, data_type, is_nullable
        FROM information_schema.columns
        WHERE table_schema = 'public' 
          AND table_name = 'kase_133_tcp_stream_extra'
        ORDER BY ordinal_position;
    """)
    cols_133 = cursor.fetchall()
    
    # 比较列名和类型（忽略默认值中的序列名差异）
    structure_match = True
    for col_134, col_133 in zip(cols_134, cols_133):
        if col_134[0] != col_133[0] or col_134[1] != col_133[1] or col_134[2] != col_133[2]:
            structure_match = False
            break
    
    if structure_match and len(cols_134) == len(cols_133):
        print("\n✅✅✅ 表结构完全一致！")
        print("✅ kase_133_tcp_stream_extra 已成功创建，结构与 kase_134_tcp_stream_extra 相同")
    else:
        print("\n⚠️  表结构存在差异，请检查")
    
    print("=" * 100)
    
    cursor.close()
    conn.close()

if __name__ == "__main__":
    verify_table()

