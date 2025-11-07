-- 修改 kase_133_tcp_stream_extra 表的字段类型
-- 将 tcp_flags_different_text 和 seq_num_different_text 从 text[] 改为 text

-- 1. 修改 tcp_flags_different_text 字段
ALTER TABLE public.kase_133_tcp_stream_extra 
ALTER COLUMN tcp_flags_different_text TYPE text 
USING array_to_string(tcp_flags_different_text, '; ');

-- 2. 修改 seq_num_different_text 字段
ALTER TABLE public.kase_133_tcp_stream_extra 
ALTER COLUMN seq_num_different_text TYPE text 
USING array_to_string(seq_num_different_text, '; ');

-- 验证修改
SELECT 
    column_name, 
    data_type, 
    udt_name
FROM information_schema.columns 
WHERE table_schema = 'public' 
  AND table_name = 'kase_133_tcp_stream_extra'
  AND column_name IN ('tcp_flags_different_text', 'seq_num_different_text');

