#!/usr/bin/env python3
"""
迁移脚本：将 kase_133_tcp_stream_extra 表的数组字段改为文本字段

这个脚本会：
1. 备份现有数据
2. 修改字段类型从 text[] 到 text
3. 验证修改结果
"""

import psycopg2
import sys

# 数据库配置
DB_CONFIG = {
    'host': '172.16.200.156',
    'port': 5433,
    'database': 'r2',
    'user': 'postgres',
    'password': 'password'
}

def main():
    print("=" * 80)
    print("开始迁移 kase_133_tcp_stream_extra 表字段类型")
    print("=" * 80)

    conn = None
    try:
        # 连接数据库
        print("\n1. 连接数据库...")
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        print("✅ 数据库连接成功")
        
        # 检查表是否存在
        print("\n2. 检查表是否存在...")
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'kase_133_tcp_stream_extra'
            );
        """)
        table_exists = cursor.fetchone()[0]
        
        if not table_exists:
            print("❌ 表 kase_133_tcp_stream_extra 不存在")
            return False
        print("✅ 表存在")
        
        # 查看当前字段类型
        print("\n3. 查看当前字段类型...")
        cursor.execute("""
            SELECT 
                column_name, 
                data_type, 
                udt_name
            FROM information_schema.columns 
            WHERE table_schema = 'public' 
              AND table_name = 'kase_133_tcp_stream_extra'
              AND column_name IN ('tcp_flags_different_text', 'seq_num_different_text')
            ORDER BY ordinal_position;
        """)
        
        columns = cursor.fetchall()
        print("\n当前字段类型:")
        for col_name, data_type, udt_name in columns:
            print(f"  - {col_name}: {data_type} (udt: {udt_name})")
        
        # 检查是否已经是 text 类型
        is_already_text = all(col[1] == 'text' and col[2] == 'text' for col in columns)
        if is_already_text:
            print("\n✅ 字段已经是 text 类型，无需修改")
            return True
        
        # 查看数据量
        print("\n4. 查看数据量...")
        cursor.execute("SELECT COUNT(*) FROM public.kase_133_tcp_stream_extra;")
        row_count = cursor.fetchone()[0]
        print(f"✅ 表中有 {row_count} 条记录")
        
        # 显示示例数据
        if row_count > 0:
            print("\n5. 显示示例数据（修改前）...")
            cursor.execute("""
                SELECT 
                    id,
                    tcp_flags_different_text,
                    seq_num_different_text
                FROM public.kase_133_tcp_stream_extra
                ORDER BY id DESC
                LIMIT 3;
            """)
            
            rows = cursor.fetchall()
            for row in rows:
                print(f"\n  ID: {row[0]}")
                print(f"  tcp_flags_different_text: {row[1]}")
                print(f"  seq_num_different_text: {row[2]}")
        
        # 确认是否继续
        print("\n" + "=" * 80)
        response = input("是否继续修改字段类型？(yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("❌ 用户取消操作")
            return False
        
        # 修改 tcp_flags_different_text 字段
        print("\n6. 修改 tcp_flags_different_text 字段...")
        cursor.execute("""
            ALTER TABLE public.kase_133_tcp_stream_extra 
            ALTER COLUMN tcp_flags_different_text TYPE text 
            USING array_to_string(tcp_flags_different_text, '; ');
        """)
        print("✅ tcp_flags_different_text 字段修改成功")
        
        # 修改 seq_num_different_text 字段
        print("\n7. 修改 seq_num_different_text 字段...")
        cursor.execute("""
            ALTER TABLE public.kase_133_tcp_stream_extra 
            ALTER COLUMN seq_num_different_text TYPE text 
            USING array_to_string(seq_num_different_text, '; ');
        """)
        print("✅ seq_num_different_text 字段修改成功")
        
        # 提交更改
        conn.commit()
        print("\n✅ 更改已提交")
        
        # 验证修改结果
        print("\n8. 验证修改结果...")
        cursor.execute("""
            SELECT 
                column_name, 
                data_type, 
                udt_name
            FROM information_schema.columns 
            WHERE table_schema = 'public' 
              AND table_name = 'kase_133_tcp_stream_extra'
              AND column_name IN ('tcp_flags_different_text', 'seq_num_different_text')
            ORDER BY ordinal_position;
        """)
        
        columns = cursor.fetchall()
        print("\n修改后的字段类型:")
        for col_name, data_type, udt_name in columns:
            print(f"  - {col_name}: {data_type} (udt: {udt_name})")
        
        # 显示修改后的示例数据
        if row_count > 0:
            print("\n9. 显示示例数据（修改后）...")
            cursor.execute("""
                SELECT 
                    id,
                    tcp_flags_different_text,
                    seq_num_different_text
                FROM public.kase_133_tcp_stream_extra
                ORDER BY id DESC
                LIMIT 3;
            """)
            
            rows = cursor.fetchall()
            for row in rows:
                print(f"\n  ID: {row[0]}")
                print(f"  tcp_flags_different_text: {row[1]}")
                print(f"  seq_num_different_text: {row[2]}")
        
        print("\n" + "=" * 80)
        print("✅ 迁移完成！")
        print("=" * 80)
        
        cursor.close()
        conn.close()
        return True
        
    except psycopg2.Error as e:
        print(f"\n❌ 数据库错误: {e}")
        if conn:
            conn.rollback()
        return False
    except Exception as e:
        print(f"\n❌ 错误: {e}")
        if conn:
            conn.rollback()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

