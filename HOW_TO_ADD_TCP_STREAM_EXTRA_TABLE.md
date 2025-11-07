# 如何添加 kase_133_tcp_stream_extra 表

本文档提供添加新的 `tcp_stream_extra` 表的方法和步骤，**不直接执行操作**。

---

## 📋 目录

1. [方法概述](#方法概述)
2. [方法一：基于现有表结构创建](#方法一基于现有表结构创建)
3. [方法二：手动定义 SQL](#方法二手动定义-sql)
4. [方法三：使用 ORM/迁移工具](#方法三使用-orm迁移工具)
5. [推荐的最佳实践](#推荐的最佳实践)
6. [验证步骤](#验证步骤)

---

## 方法概述

有三种主要方法可以添加 `public.kase_133_tcp_stream_extra` 表：

| 方法 | 优点 | 缺点 | 推荐场景 |
|------|------|------|----------|
| 基于现有表复制 | 快速、结构一致 | 可能复制不需要的特性 | 结构完全相同时 |
| 手动定义 SQL | 完全控制、灵活 | 需要了解完整结构 | 需要自定义时 |
| ORM/迁移工具 | 版本控制、可回滚 | 需要配置工具 | 生产环境推荐 |

---

## 方法一：基于现有表结构创建

### 步骤 1: 获取现有表的 DDL

```sql
-- 方式 A: 使用 pg_dump 导出表结构
-- 在命令行执行：
pg_dump -h 172.16.200.156 -p 5433 -U postgres -d r2 \
  --schema-only --table=public.kase_134_tcp_stream_extra \
  > kase_134_tcp_stream_extra_schema.sql
```

```sql
-- 方式 B: 使用 SQL 查询生成 CREATE TABLE 语句
SELECT 
    'CREATE TABLE public.kase_133_tcp_stream_extra (' || 
    string_agg(
        column_name || ' ' || 
        CASE 
            WHEN data_type = 'ARRAY' THEN udt_name || '[]'
            WHEN character_maximum_length IS NOT NULL 
                THEN data_type || '(' || character_maximum_length || ')'
            ELSE data_type 
        END ||
        CASE WHEN is_nullable = 'NO' THEN ' NOT NULL' ELSE '' END ||
        CASE WHEN column_default IS NOT NULL 
            THEN ' DEFAULT ' || column_default ELSE '' END,
        E',\n    '
    ) || 
    ');' as create_statement
FROM information_schema.columns
WHERE table_schema = 'public' 
  AND table_name = 'kase_134_tcp_stream_extra'
ORDER BY ordinal_position;
```

### 步骤 2: 修改表名并执行

```sql
-- 将导出的 SQL 中的表名从 kase_134 改为 kase_133
-- 然后执行 CREATE TABLE 语句
```

### Python 脚本示例

```python
#!/usr/bin/env python3
"""基于现有表创建新的 tcp_stream_extra 表"""

import psycopg2

DB_CONFIG = {
    'host': '172.16.200.156',
    'port': 5433,
    'database': 'r2',
    'user': 'postgres',
    'password': 'password'
}

def create_table_from_existing():
    """基于 kase_134_tcp_stream_extra 创建 kase_133_tcp_stream_extra"""
    
    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()
    
    # 方法 1: 使用 CREATE TABLE ... LIKE (PostgreSQL 不支持)
    # 方法 2: 使用 CREATE TABLE ... AS SELECT (会复制数据)
    # 方法 3: 手动构建 CREATE TABLE 语句
    
    # 获取列定义
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
    
    # 构建 CREATE TABLE 语句
    create_sql = "CREATE TABLE public.kase_133_tcp_stream_extra (\n"
    
    col_definitions = []
    for col_name, data_type, max_len, nullable, default, udt_name in columns:
        col_def = f"    {col_name} "
        
        # 处理数据类型
        if data_type == 'ARRAY':
            col_def += f"{udt_name}[]"
        elif max_len:
            col_def += f"{data_type}({max_len})"
        else:
            col_def += data_type
        
        # 处理 NULL/NOT NULL
        if nullable == 'NO':
            col_def += " NOT NULL"
        
        # 处理默认值
        if default:
            col_def += f" DEFAULT {default}"
        
        col_definitions.append(col_def)
    
    create_sql += ",\n".join(col_definitions)
    create_sql += "\n);"
    
    print("生成的 CREATE TABLE 语句：")
    print(create_sql)
    print("\n注意：这只是预览，未实际执行！")
    
    # 如果要执行，取消下面的注释：
    # cursor.execute(create_sql)
    # conn.commit()
    # print("✅ 表创建成功！")
    
    cursor.close()
    conn.close()

if __name__ == "__main__":
    create_table_from_existing()
```

---

## 方法二：手动定义 SQL

### 完整的 CREATE TABLE 语句

基于 `kase_134_tcp_stream_extra` 的结构：

```sql
CREATE TABLE public.kase_133_tcp_stream_extra (
    pcap_id                    INTEGER,
    flow_hash                  BIGINT,
    first_time                 BIGINT,
    last_time                  BIGINT,
    tcp_flags_different_cnt    BIGINT,
    tcp_flags_different_text   TEXT[],
    seq_num_different_cnt      BIGINT,
    seq_num_different_text     TEXT[],
    id                         INTEGER NOT NULL DEFAULT nextval('kase_133_tcp_stream_extra_id_seq'::regclass)
);
```

### 注意事项

1. **序列（Sequence）创建**：
   ```sql
   -- 如果使用自增 ID，需要先创建序列
   CREATE SEQUENCE public.kase_133_tcp_stream_extra_id_seq;
   
   -- 然后在 CREATE TABLE 中引用
   -- 或者使用 SERIAL 类型自动创建
   ```

2. **使用 SERIAL 简化**：
   ```sql
   CREATE TABLE public.kase_133_tcp_stream_extra (
       pcap_id                    INTEGER,
       flow_hash                  BIGINT,
       first_time                 BIGINT,
       last_time                  BIGINT,
       tcp_flags_different_cnt    BIGINT,
       tcp_flags_different_text   TEXT[],
       seq_num_different_cnt      BIGINT,
       seq_num_different_text     TEXT[],
       id                         SERIAL  -- 自动创建序列
   );
   ```

### 添加约束和索引（可选但推荐）

```sql
-- 添加主键约束
ALTER TABLE public.kase_133_tcp_stream_extra 
ADD CONSTRAINT kase_133_tcp_stream_extra_pkey PRIMARY KEY (id);

-- 添加索引以提高查询性能
CREATE INDEX idx_kase_133_tcp_stream_extra_pcap_id 
ON public.kase_133_tcp_stream_extra(pcap_id);

CREATE INDEX idx_kase_133_tcp_stream_extra_flow_hash 
ON public.kase_133_tcp_stream_extra(flow_hash);

CREATE INDEX idx_kase_133_tcp_stream_extra_time 
ON public.kase_133_tcp_stream_extra(first_time, last_time);

-- 添加外键约束（如果有相关表）
-- ALTER TABLE public.kase_133_tcp_stream_extra
-- ADD CONSTRAINT fk_kase_133_tcp_stream
-- FOREIGN KEY (flow_hash) REFERENCES public.kase_133_tcp_stream(flow_hash);
```

### 添加注释（推荐）

```sql
-- 表注释
COMMENT ON TABLE public.kase_133_tcp_stream_extra IS 
'TCP stream extra information for kase 133';

-- 列注释
COMMENT ON COLUMN public.kase_133_tcp_stream_extra.pcap_id IS 
'PCAP file identifier';

COMMENT ON COLUMN public.kase_133_tcp_stream_extra.flow_hash IS 
'Flow hash value for stream identification';

COMMENT ON COLUMN public.kase_133_tcp_stream_extra.first_time IS 
'First packet timestamp in nanoseconds';

COMMENT ON COLUMN public.kase_133_tcp_stream_extra.last_time IS 
'Last packet timestamp in nanoseconds';

COMMENT ON COLUMN public.kase_133_tcp_stream_extra.tcp_flags_different_cnt IS 
'Count of different TCP flags';

COMMENT ON COLUMN public.kase_133_tcp_stream_extra.tcp_flags_different_text IS 
'Array of different TCP flags descriptions';

COMMENT ON COLUMN public.kase_133_tcp_stream_extra.seq_num_different_cnt IS 
'Count of different sequence numbers';

COMMENT ON COLUMN public.kase_133_tcp_stream_extra.seq_num_different_text IS 
'Array of different sequence number descriptions';

COMMENT ON COLUMN public.kase_133_tcp_stream_extra.id IS 
'Primary key auto-increment ID';
```

---

## 方法三：使用 ORM/迁移工具

### 使用 Drizzle ORM（数据库中已有 drizzle 迁移表）

```typescript
// schema.ts
import { pgTable, serial, integer, bigint, text } from 'drizzle-orm/pg-core';

export const kase133TcpStreamExtra = pgTable('kase_133_tcp_stream_extra', {
  id: serial('id').primaryKey(),
  pcapId: integer('pcap_id'),
  flowHash: bigint('flow_hash', { mode: 'bigint' }),
  firstTime: bigint('first_time', { mode: 'bigint' }),
  lastTime: bigint('last_time', { mode: 'bigint' }),
  tcpFlagsDifferentCnt: bigint('tcp_flags_different_cnt', { mode: 'bigint' }),
  tcpFlagsDifferentText: text('tcp_flags_different_text').array(),
  seqNumDifferentCnt: bigint('seq_num_different_cnt', { mode: 'bigint' }),
  seqNumDifferentText: text('seq_num_different_text').array(),
});
```

```bash
# 生成迁移文件
npx drizzle-kit generate:pg

# 执行迁移
npx drizzle-kit push:pg
```

### 使用 Alembic（Python）

```python
# migrations/versions/xxx_add_kase_133_tcp_stream_extra.py
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

def upgrade():
    op.create_table(
        'kase_133_tcp_stream_extra',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('pcap_id', sa.Integer(), nullable=True),
        sa.Column('flow_hash', sa.BigInteger(), nullable=True),
        sa.Column('first_time', sa.BigInteger(), nullable=True),
        sa.Column('last_time', sa.BigInteger(), nullable=True),
        sa.Column('tcp_flags_different_cnt', sa.BigInteger(), nullable=True),
        sa.Column('tcp_flags_different_text', postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column('seq_num_different_cnt', sa.BigInteger(), nullable=True),
        sa.Column('seq_num_different_text', postgresql.ARRAY(sa.Text()), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        schema='public'
    )
    
    # 创建索引
    op.create_index('idx_kase_133_tcp_stream_extra_pcap_id', 
                    'kase_133_tcp_stream_extra', ['pcap_id'], 
                    schema='public')
    op.create_index('idx_kase_133_tcp_stream_extra_flow_hash', 
                    'kase_133_tcp_stream_extra', ['flow_hash'], 
                    schema='public')

def downgrade():
    op.drop_index('idx_kase_133_tcp_stream_extra_flow_hash', 
                  table_name='kase_133_tcp_stream_extra', schema='public')
    op.drop_index('idx_kase_133_tcp_stream_extra_pcap_id', 
                  table_name='kase_133_tcp_stream_extra', schema='public')
    op.drop_table('kase_133_tcp_stream_extra', schema='public')
```

```bash
# 执行迁移
alembic upgrade head

# 如需回滚
alembic downgrade -1
```

---

## 推荐的最佳实践

### 1. 完整的创建流程

```sql
-- Step 1: 开始事务
BEGIN;

-- Step 2: 创建表
CREATE TABLE public.kase_133_tcp_stream_extra (
    pcap_id                    INTEGER,
    flow_hash                  BIGINT,
    first_time                 BIGINT,
    last_time                  BIGINT,
    tcp_flags_different_cnt    BIGINT,
    tcp_flags_different_text   TEXT[],
    seq_num_different_cnt      BIGINT,
    seq_num_different_text     TEXT[],
    id                         SERIAL PRIMARY KEY
);

-- Step 3: 创建索引
CREATE INDEX idx_kase_133_tcp_stream_extra_pcap_id 
ON public.kase_133_tcp_stream_extra(pcap_id);

CREATE INDEX idx_kase_133_tcp_stream_extra_flow_hash 
ON public.kase_133_tcp_stream_extra(flow_hash);

CREATE INDEX idx_kase_133_tcp_stream_extra_time 
ON public.kase_133_tcp_stream_extra(first_time, last_time);

-- Step 4: 添加注释
COMMENT ON TABLE public.kase_133_tcp_stream_extra IS 
'TCP stream extra information for kase 133';

-- Step 5: 设置表权限（根据需要）
-- GRANT SELECT, INSERT, UPDATE, DELETE ON public.kase_133_tcp_stream_extra TO your_user;

-- Step 6: 提交事务
COMMIT;

-- 如果出错，可以回滚：
-- ROLLBACK;
```

### 2. 使用 Python 脚本执行（带验证）

```python
#!/usr/bin/env python3
"""创建 kase_133_tcp_stream_extra 表的完整脚本"""

import psycopg2
from psycopg2 import sql

DB_CONFIG = {
    'host': '172.16.200.156',
    'port': 5433,
    'database': 'r2',
    'user': 'postgres',
    'password': 'password'
}

def create_kase_133_tcp_stream_extra():
    """创建表的完整流程"""
    
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = False  # 使用事务
    cursor = conn.cursor()
    
    try:
        print("Step 1: 检查表是否已存在...")
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'kase_133_tcp_stream_extra'
            );
        """)
        
        if cursor.fetchone()[0]:
            print("⚠️  表已存在！")
            response = input("是否删除并重建？(yes/no): ")
            if response.lower() == 'yes':
                cursor.execute("DROP TABLE public.kase_133_tcp_stream_extra CASCADE;")
                print("✅ 已删除旧表")
            else:
                print("❌ 操作取消")
                return
        
        print("\nStep 2: 创建表...")
        cursor.execute("""
            CREATE TABLE public.kase_133_tcp_stream_extra (
                pcap_id                    INTEGER,
                flow_hash                  BIGINT,
                first_time                 BIGINT,
                last_time                  BIGINT,
                tcp_flags_different_cnt    BIGINT,
                tcp_flags_different_text   TEXT[],
                seq_num_different_cnt      BIGINT,
                seq_num_different_text     TEXT[],
                id                         SERIAL PRIMARY KEY
            );
        """)
        print("✅ 表创建成功")
        
        print("\nStep 3: 创建索引...")
        cursor.execute("""
            CREATE INDEX idx_kase_133_tcp_stream_extra_pcap_id 
            ON public.kase_133_tcp_stream_extra(pcap_id);
        """)
        cursor.execute("""
            CREATE INDEX idx_kase_133_tcp_stream_extra_flow_hash 
            ON public.kase_133_tcp_stream_extra(flow_hash);
        """)
        cursor.execute("""
            CREATE INDEX idx_kase_133_tcp_stream_extra_time 
            ON public.kase_133_tcp_stream_extra(first_time, last_time);
        """)
        print("✅ 索引创建成功")
        
        print("\nStep 4: 添加注释...")
        cursor.execute("""
            COMMENT ON TABLE public.kase_133_tcp_stream_extra IS 
            'TCP stream extra information for kase 133';
        """)
        print("✅ 注释添加成功")
        
        print("\nStep 5: 验证表结构...")
        cursor.execute("""
            SELECT column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_schema = 'public' 
              AND table_name = 'kase_133_tcp_stream_extra'
            ORDER BY ordinal_position;
        """)
        
        columns = cursor.fetchall()
        print(f"\n表结构验证（共 {len(columns)} 列）：")
        for col_name, data_type, nullable in columns:
            print(f"  - {col_name}: {data_type} ({'NULL' if nullable == 'YES' else 'NOT NULL'})")
        
        # 提交事务
        print("\n准备提交事务...")
        response = input("确认提交？(yes/no): ")
        
        if response.lower() == 'yes':
            conn.commit()
            print("\n✅ 表创建完成并已提交！")
        else:
            conn.rollback()
            print("\n❌ 操作已回滚")
        
    except Exception as e:
        conn.rollback()
        print(f"\n❌ 错误: {e}")
        print("事务已回滚")
    
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    print("=" * 80)
    print("创建 public.kase_133_tcp_stream_extra 表")
    print("=" * 80)
    print("\n⚠️  注意：此脚本将修改数据库！")
    print(f"数据库: {DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}\n")
    
    response = input("是否继续？(yes/no): ")
    if response.lower() == 'yes':
        create_kase_133_tcp_stream_extra()
    else:
        print("操作已取消")
```

---

## 验证步骤

### 创建后验证清单

```sql
-- 1. 验证表是否存在
SELECT EXISTS (
    SELECT FROM information_schema.tables 
    WHERE table_schema = 'public' 
    AND table_name = 'kase_133_tcp_stream_extra'
);

-- 2. 验证表结构
SELECT 
    column_name,
    data_type,
    character_maximum_length,
    is_nullable,
    column_default
FROM information_schema.columns
WHERE table_schema = 'public' 
  AND table_name = 'kase_133_tcp_stream_extra'
ORDER BY ordinal_position;

-- 3. 验证索引
SELECT indexname, indexdef
FROM pg_indexes
WHERE schemaname = 'public' 
  AND tablename = 'kase_133_tcp_stream_extra';

-- 4. 验证约束
SELECT conname, contype, pg_get_constraintdef(oid)
FROM pg_constraint
WHERE conrelid = 'public.kase_133_tcp_stream_extra'::regclass;

-- 5. 验证表大小
SELECT pg_size_pretty(pg_total_relation_size('public.kase_133_tcp_stream_extra'));

-- 6. 测试插入数据
INSERT INTO public.kase_133_tcp_stream_extra 
(pcap_id, flow_hash, first_time, last_time)
VALUES (0, 123456789, 1630482070018110000, 1630482070049663000);

-- 7. 测试查询
SELECT * FROM public.kase_133_tcp_stream_extra;

-- 8. 清理测试数据
DELETE FROM public.kase_133_tcp_stream_extra WHERE pcap_id = 0;
```

### Python 验证脚本

```python
#!/usr/bin/env python3
"""验证 kase_133_tcp_stream_extra 表"""

import psycopg2

DB_CONFIG = {
    'host': '172.16.200.156',
    'port': 5433,
    'database': 'r2',
    'user': 'postgres',
    'password': 'password'
}

def verify_table():
    """验证表是否正确创建"""
    
    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()
    
    print("=" * 80)
    print("验证 public.kase_133_tcp_stream_extra 表")
    print("=" * 80)
    
    # 1. 检查表是否存在
    cursor.execute("""
        SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name = 'kase_133_tcp_stream_extra'
        );
    """)
    exists = cursor.fetchone()[0]
    print(f"\n1. 表存在性: {'✅ 存在' if exists else '❌ 不存在'}")
    
    if not exists:
        print("\n表不存在，验证终止。")
        return
    
    # 2. 检查列数量
    cursor.execute("""
        SELECT COUNT(*) 
        FROM information_schema.columns
        WHERE table_schema = 'public' 
          AND table_name = 'kase_133_tcp_stream_extra';
    """)
    col_count = cursor.fetchone()[0]
    print(f"2. 列数量: {col_count} {'✅' if col_count == 9 else '⚠️'}")
    
    # 3. 检查索引
    cursor.execute("""
        SELECT COUNT(*) 
        FROM pg_indexes
        WHERE schemaname = 'public' 
          AND tablename = 'kase_133_tcp_stream_extra';
    """)
    idx_count = cursor.fetchone()[0]
    print(f"3. 索引数量: {idx_count}")
    
    # 4. 检查主键
    cursor.execute("""
        SELECT COUNT(*) 
        FROM pg_constraint
        WHERE conrelid = 'public.kase_133_tcp_stream_extra'::regclass
          AND contype = 'p';
    """)
    pk_count = cursor.fetchone()[0]
    print(f"4. 主键约束: {'✅ 已设置' if pk_count > 0 else '⚠️ 未设置'}")
    
    # 5. 检查行数
    cursor.execute("SELECT COUNT(*) FROM public.kase_133_tcp_stream_extra;")
    row_count = cursor.fetchone()[0]
    print(f"5. 数据行数: {row_count}")
    
    print("\n" + "=" * 80)
    print("✅ 验证完成")
    print("=" * 80)
    
    cursor.close()
    conn.close()

if __name__ == "__main__":
    verify_table()
```

---

## 总结

### 推荐方案

**对于生产环境**：
- ✅ 使用**方法三（ORM/迁移工具）**，便于版本控制和回滚
- ✅ 使用事务确保原子性
- ✅ 添加完整的索引和约束
- ✅ 添加表和列注释

**对于开发/测试环境**：
- ✅ 使用**方法二（手动 SQL）**，快速灵活
- ✅ 可以先在测试环境验证后再应用到生产环境

### 关键注意事项

1. ⚠️ **始终使用事务**，出错可以回滚
2. ⚠️ **先在测试环境验证**
3. ⚠️ **备份数据库**（如果是生产环境）
4. ⚠️ **添加适当的索引**以提高查询性能
5. ⚠️ **考虑与其他表的关系**（外键约束）
6. ⚠️ **设置适当的权限**

---

*本文档提供方法指导，不直接执行数据库操作*

