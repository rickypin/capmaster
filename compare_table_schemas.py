#!/usr/bin/env python3
"""Compare schemas of two database tables in detail."""

import psycopg2

DB_CONFIG = {
    'host': '172.16.200.156',
    'port': 5433,
    'database': 'r2',
    'user': 'postgres',
    'password': 'password'
}

def get_table_schema(cursor, table_name):
    """Get detailed schema information for a table."""
    # Get column information
    cursor.execute("""
        SELECT 
            column_name,
            data_type,
            udt_name,
            character_maximum_length,
            numeric_precision,
            numeric_scale,
            is_nullable,
            column_default,
            ordinal_position
        FROM information_schema.columns
        WHERE table_schema = 'public' 
        AND table_name = %s
        ORDER BY ordinal_position;
    """, (table_name,))
    
    columns = cursor.fetchall()
    
    # Get indexes
    cursor.execute("""
        SELECT
            i.relname as index_name,
            a.attname as column_name,
            am.amname as index_type,
            ix.indisunique as is_unique,
            ix.indisprimary as is_primary
        FROM pg_class t
        JOIN pg_index ix ON t.oid = ix.indrelid
        JOIN pg_class i ON i.oid = ix.indexrelid
        JOIN pg_am am ON i.relam = am.oid
        JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(ix.indkey)
        WHERE t.relname = %s
        AND t.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
        ORDER BY i.relname, a.attnum;
    """, (table_name,))
    
    indexes = cursor.fetchall()
    
    # Get constraints
    cursor.execute("""
        SELECT
            con.conname as constraint_name,
            con.contype as constraint_type,
            pg_get_constraintdef(con.oid) as constraint_definition
        FROM pg_constraint con
        JOIN pg_class rel ON rel.oid = con.conrelid
        WHERE rel.relname = %s
        AND rel.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
        ORDER BY con.conname;
    """, (table_name,))
    
    constraints = cursor.fetchall()
    
    return {
        'columns': columns,
        'indexes': indexes,
        'constraints': constraints
    }

def compare_schemas():
    """Compare schemas of kase_133 and kase_134 tables."""
    print("=" * 120)
    print("DETAILED TABLE SCHEMA COMPARISON")
    print("=" * 120)
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        table1 = 'kase_133_tcp_stream_extra'
        table2 = 'kase_134_tcp_stream_extra'
        
        print(f"\nComparing: public.{table1} vs public.{table2}")
        print("=" * 120)
        
        schema1 = get_table_schema(cursor, table1)
        schema2 = get_table_schema(cursor, table2)
        
        # Compare columns
        print("\n" + "=" * 120)
        print("COLUMN COMPARISON")
        print("=" * 120)
        
        columns1 = {col[0]: col for col in schema1['columns']}
        columns2 = {col[0]: col for col in schema2['columns']}
        
        all_columns = sorted(set(columns1.keys()) | set(columns2.keys()))
        
        differences_found = False
        
        for col_name in all_columns:
            col1 = columns1.get(col_name)
            col2 = columns2.get(col_name)
            
            if col1 is None:
                print(f"\n❌ Column '{col_name}' exists in {table2} but NOT in {table1}")
                differences_found = True
            elif col2 is None:
                print(f"\n❌ Column '{col_name}' exists in {table1} but NOT in {table2}")
                differences_found = True
            else:
                # Compare all attributes
                (name1, dtype1, udt1, maxlen1, prec1, scale1, nullable1, default1, pos1) = col1
                (name2, dtype2, udt2, maxlen2, prec2, scale2, nullable2, default2, pos2) = col2
                
                col_diff = []
                
                if dtype1 != dtype2:
                    col_diff.append(f"data_type: {dtype1} vs {dtype2}")
                if udt1 != udt2:
                    col_diff.append(f"udt_name: {udt1} vs {udt2}")
                if maxlen1 != maxlen2:
                    col_diff.append(f"max_length: {maxlen1} vs {maxlen2}")
                if prec1 != prec2:
                    col_diff.append(f"precision: {prec1} vs {prec2}")
                if scale1 != scale2:
                    col_diff.append(f"scale: {scale1} vs {scale2}")
                if nullable1 != nullable2:
                    col_diff.append(f"nullable: {nullable1} vs {nullable2}")
                if str(default1) != str(default2):
                    # Only flag if both are not None or if they differ
                    if default1 is not None and default2 is not None:
                        # Extract sequence names for comparison
                        def1_clean = str(default1).replace('133', 'XXX')
                        def2_clean = str(default2).replace('134', 'XXX')
                        if def1_clean != def2_clean:
                            col_diff.append(f"default: {default1} vs {default2}")
                if pos1 != pos2:
                    col_diff.append(f"position: {pos1} vs {pos2}")
                
                if col_diff:
                    print(f"\n❌ Column '{col_name}' has differences:")
                    for diff in col_diff:
                        print(f"   - {diff}")
                    differences_found = True
                else:
                    print(f"✅ Column '{col_name}': IDENTICAL")
        
        # Compare indexes
        print("\n" + "=" * 120)
        print("INDEX COMPARISON")
        print("=" * 120)
        
        # Normalize index names for comparison
        def normalize_index(idx_list, table_num):
            normalized = []
            for idx in idx_list:
                idx_name, col_name, idx_type, is_unique, is_primary = idx
                # Replace table-specific numbers
                norm_name = idx_name.replace(f'_{table_num}_', '_XXX_').replace(f'{table_num}_', 'XXX_')
                normalized.append((norm_name, col_name, idx_type, is_unique, is_primary))
            return normalized
        
        norm_idx1 = normalize_index(schema1['indexes'], '133')
        norm_idx2 = normalize_index(schema2['indexes'], '134')
        
        print(f"\n{table1} has {len(schema1['indexes'])} index(es)")
        print(f"{table2} has {len(schema2['indexes'])} index(es)")
        
        if len(schema1['indexes']) != len(schema2['indexes']):
            print(f"\n❌ Different number of indexes!")
            differences_found = True
        
        # Group indexes by normalized name
        idx1_dict = {}
        for idx in norm_idx1:
            norm_name = idx[0]
            if norm_name not in idx1_dict:
                idx1_dict[norm_name] = []
            idx1_dict[norm_name].append(idx)
        
        idx2_dict = {}
        for idx in norm_idx2:
            norm_name = idx[0]
            if norm_name not in idx2_dict:
                idx2_dict[norm_name] = []
            idx2_dict[norm_name].append(idx)
        
        all_idx_names = sorted(set(idx1_dict.keys()) | set(idx2_dict.keys()))
        
        for idx_name in all_idx_names:
            idx1_list = idx1_dict.get(idx_name, [])
            idx2_list = idx2_dict.get(idx_name, [])
            
            if not idx1_list:
                print(f"\n❌ Index '{idx_name}' exists in {table2} but NOT in {table1}")
                differences_found = True
            elif not idx2_list:
                print(f"\n❌ Index '{idx_name}' exists in {table1} but NOT in {table2}")
                differences_found = True
            elif idx1_list == idx2_list:
                print(f"✅ Index '{idx_name}': IDENTICAL")
            else:
                print(f"\n❌ Index '{idx_name}' has differences:")
                print(f"   {table1}: {idx1_list}")
                print(f"   {table2}: {idx2_list}")
                differences_found = True
        
        # Compare constraints
        print("\n" + "=" * 120)
        print("CONSTRAINT COMPARISON")
        print("=" * 120)
        
        print(f"\n{table1} has {len(schema1['constraints'])} constraint(s)")
        print(f"{table2} has {len(schema2['constraints'])} constraint(s)")
        
        if len(schema1['constraints']) != len(schema2['constraints']):
            print(f"\n❌ Different number of constraints!")
            differences_found = True
        
        # Normalize constraint definitions
        def normalize_constraint(con_list, table_num):
            normalized = []
            for con in con_list:
                con_name, con_type, con_def = con
                norm_name = con_name.replace(f'_{table_num}_', '_XXX_').replace(f'{table_num}_', 'XXX_')
                norm_def = con_def.replace(f'_{table_num}_', '_XXX_').replace(f'{table_num}_', 'XXX_')
                normalized.append((norm_name, con_type, norm_def))
            return normalized
        
        norm_con1 = normalize_constraint(schema1['constraints'], '133')
        norm_con2 = normalize_constraint(schema2['constraints'], '134')
        
        if set(norm_con1) == set(norm_con2):
            print("✅ All constraints are IDENTICAL")
        else:
            print("\n❌ Constraints differ:")
            print(f"   {table1}: {norm_con1}")
            print(f"   {table2}: {norm_con2}")
            differences_found = True
        
        # Final summary
        print("\n" + "=" * 120)
        print("SUMMARY")
        print("=" * 120)
        
        if not differences_found:
            print("\n✅ ✅ ✅ ALL FIELDS AND ATTRIBUTES ARE IDENTICAL! ✅ ✅ ✅")
        else:
            print("\n❌ DIFFERENCES FOUND - See details above")
        
        print("=" * 120)
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    compare_schemas()

