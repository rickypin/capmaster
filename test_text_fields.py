#!/usr/bin/env python3
"""
测试脚本：验证修改后的字段类型和数据写入

这个脚本会：
1. 检查字段类型是否正确
2. 测试插入新数据
3. 验证数据格式
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
    print("测试 kase_133_tcp_stream_extra 表的文本字段")
    print("=" * 80)
    
    try:
        # 连接数据库
        print("\n1. 连接数据库...")
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        print("✅ 数据库连接成功")
        
        # 检查字段类型
        print("\n2. 检查字段类型...")
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
        print("\n字段类型:")
        all_text = True
        for col_name, data_type, udt_name in columns:
            is_text = data_type == 'text' and udt_name == 'text'
            status = "✅" if is_text else "❌"
            print(f"  {status} {col_name}: {data_type} (udt: {udt_name})")
            if not is_text:
                all_text = False
        
        if not all_text:
            print("\n❌ 字段类型不正确，请先运行 migrate_table_to_text.py")
            return False
        
        print("\n✅ 所有字段类型正确")
        
        # 测试插入数据
        print("\n3. 测试插入数据...")
        
        # 准备测试数据
        test_data = {
            'pcap_id': 999,
            'flow_hash': -1234567890123456789,
            'first_time': 1234567890000000000,
            'last_time': 1234567890100000000,
            'tcp_flags_different_cnt': 5,
            'tcp_flags_different_type': '0x0002->0x0010',
            'tcp_flags_different_text': '0x0002→0x0010 (3 occurrences); 0x0010→0x0018 (2 occurrences)',
            'seq_num_different_cnt': 3,
            'seq_num_different_text': 'Frame 10→11: 1000→2000; Frame 20→21: 3000→4000; Frame 30→31: 5000→6000'
        }
        
        # 插入测试数据
        cursor.execute("""
            INSERT INTO public.kase_133_tcp_stream_extra (
                pcap_id,
                flow_hash,
                first_time,
                last_time,
                tcp_flags_different_cnt,
                tcp_flags_different_type,
                tcp_flags_different_text,
                seq_num_different_cnt,
                seq_num_different_text
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id;
        """, (
            test_data['pcap_id'],
            test_data['flow_hash'],
            test_data['first_time'],
            test_data['last_time'],
            test_data['tcp_flags_different_cnt'],
            test_data['tcp_flags_different_type'],
            test_data['tcp_flags_different_text'],
            test_data['seq_num_different_cnt'],
            test_data['seq_num_different_text']
        ))
        
        inserted_id = cursor.fetchone()[0]
        conn.commit()
        print(f"✅ 测试数据插入成功，ID: {inserted_id}")
        
        # 读取并验证数据
        print("\n4. 读取并验证数据...")
        cursor.execute("""
            SELECT 
                id,
                pcap_id,
                flow_hash,
                tcp_flags_different_cnt,
                tcp_flags_different_type,
                tcp_flags_different_text,
                seq_num_different_cnt,
                seq_num_different_text
            FROM public.kase_133_tcp_stream_extra
            WHERE id = %s;
        """, (inserted_id,))
        
        row = cursor.fetchone()
        if row:
            print(f"\n读取的数据:")
            print(f"  ID: {row[0]}")
            print(f"  pcap_id: {row[1]}")
            print(f"  flow_hash: {row[2]}")
            print(f"  tcp_flags_different_cnt: {row[3]}")
            print(f"  tcp_flags_different_type: {row[4]}")
            print(f"  tcp_flags_different_text: {row[5]}")
            print(f"  seq_num_different_cnt: {row[6]}")
            print(f"  seq_num_different_text: {row[7]}")
            
            # 验证数据类型
            print(f"\n数据类型验证:")
            print(f"  tcp_flags_different_text 类型: {type(row[5]).__name__} ✅" if isinstance(row[5], str) else f"  tcp_flags_different_text 类型: {type(row[5]).__name__} ❌")
            print(f"  seq_num_different_text 类型: {type(row[6]).__name__} ✅" if isinstance(row[7], str) else f"  seq_num_different_text 类型: {type(row[7]).__name__} ❌")
            
            # 验证内容
            if row[5] == test_data['tcp_flags_different_text']:
                print(f"  tcp_flags_different_text 内容匹配 ✅")
            else:
                print(f"  tcp_flags_different_text 内容不匹配 ❌")
                print(f"    期望: {test_data['tcp_flags_different_text']}")
                print(f"    实际: {row[5]}")
            
            if row[7] == test_data['seq_num_different_text']:
                print(f"  seq_num_different_text 内容匹配 ✅")
            else:
                print(f"  seq_num_different_text 内容不匹配 ❌")
                print(f"    期望: {test_data['seq_num_different_text']}")
                print(f"    实际: {row[7]}")
        
        # 清理测试数据
        print("\n5. 清理测试数据...")
        response = input(f"是否删除测试数据 (ID: {inserted_id})？(yes/no): ")
        if response.lower() in ['yes', 'y']:
            cursor.execute("""
                DELETE FROM public.kase_133_tcp_stream_extra
                WHERE id = %s;
            """, (inserted_id,))
            conn.commit()
            print("✅ 测试数据已删除")
        else:
            print("⚠️  测试数据保留")
        
        print("\n" + "=" * 80)
        print("✅ 测试完成！")
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
        import traceback
        traceback.print_exc()
        if conn:
            conn.rollback()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

