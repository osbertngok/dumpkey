#!/usr/bin/env python3
"""
inflate_db.py — Decompress WCDB zstd-compressed columns in a decrypted WeChat 4.x database.

WeChat 4.x uses WCDB (Tencent's SQLCipher fork), which compresses certain TEXT columns
with zstd. Each compressed column has a corresponding WCDB_CT_<column> integer flag:
  - 0 or NULL: plain text, no compression
  - 4: zstd-compressed

This script copies the database with all compressed columns decompressed, making it
readable by standard SQLite tools without needing the WCDB library.

Usage:
    python3 inflate_db.py <input.db> <output.db>

Requirements:
    pip install zstandard
"""

import shutil
import sqlite3
import sys

import zstandard

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def try_decompress(data, dctx):
    """
    Attempt zstd decompression. Returns decompressed UTF-8 string on success,
    or the original data unchanged on failure.
    """
    if data is None:
        return data, False
    raw = bytes(data)
    if not raw.startswith(ZSTD_MAGIC):
        return data, False
    try:
        return dctx.decompress(raw).decode("utf-8"), True
    except Exception as e:
        print(f"    [warn] decompression failed: {e}", file=sys.stderr)
        return data, False


def inflate_table(src, dst, table_name, dctx):
    """
    Copy one table from src to dst, decompressing any WCDB_CT_<col>=4 columns.
    Returns number of rows processed.
    """
    col_info = src.execute(f"PRAGMA table_info('{table_name}')").fetchall()
    col_names = [c[1] for c in col_info]

    # Build map: data column -> its CT flag column
    # e.g. "message_content" -> "WCDB_CT_message_content"
    ct_map = {}
    for col in col_names:
        if col.startswith("WCDB_CT_"):
            target = col[len("WCDB_CT_"):]
            if target in col_names:
                ct_map[target] = col

    placeholders = ", ".join(["?"] * len(col_names))
    insert_sql = f"INSERT INTO '{table_name}' VALUES ({placeholders})"

    rows = src.execute(f"SELECT * FROM '{table_name}'").fetchall()
    if not rows:
        return 0

    if not ct_map:
        dst.executemany(insert_sql, rows)
        return len(rows)

    inflated = []
    decompressed_counts = {col: 0 for col in ct_map}

    for row in rows:
        row_dict = dict(zip(col_names, row))
        for data_col, ct_col in ct_map.items():
            if row_dict.get(ct_col) == 4:
                inflated_value, ok = try_decompress(row_dict[data_col], dctx)
                if ok:
                    row_dict[data_col] = inflated_value
                    row_dict[ct_col] = 0
                    decompressed_counts[data_col] += 1
        inflated.append(tuple(row_dict[c] for c in col_names))

    dst.executemany(insert_sql, inflated)

    for col, count in decompressed_counts.items():
        if count:
            print(f"  {table_name}.{col}: decompressed {count}/{len(rows)} rows")

    return len(rows)


def inflate_db(src_path, dst_path):
    print(f"Source : {src_path}")
    print(f"Output : {dst_path}")

    src = sqlite3.connect(f"file:{src_path}?mode=ro", uri=True)
    dst = sqlite3.connect(dst_path)
    dctx = zstandard.ZstdDecompressor()

    # Copy full schema from source (tables, indexes, triggers)
    schema_rows = src.execute(
        "SELECT type, name, sql FROM sqlite_master "
        "WHERE sql IS NOT NULL AND name != 'sqlite_sequence' "
        "ORDER BY rootpage"
    ).fetchall()
    for obj_type, name, sql in schema_rows:
        try:
            dst.execute(sql)
        except sqlite3.OperationalError as e:
            print(f"  [warn] schema copy failed for {name}: {e}", file=sys.stderr)
    dst.commit()

    # Copy and inflate each table
    tables = src.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence'"
    ).fetchall()

    total_rows = 0
    for (table_name,) in tables:
        # Clear wcdb_builtin_compression_record in output — compression is removed
        if table_name == "wcdb_builtin_compression_record":
            print(f"  {table_name}: cleared (compression metadata no longer applies)")
            continue

        n = inflate_table(src, dst, table_name, dctx)
        total_rows += n
        if n and table_name not in ("wcdb_builtin_compression_record",):
            pass  # per-column reporting already done inside inflate_table

    dst.commit()
    src.close()
    dst.close()

    print(f"\nDone. {total_rows} total rows written to {dst_path}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.db> <output.db>")
        sys.exit(1)

    src_path, dst_path = sys.argv[1], sys.argv[2]
    inflate_db(src_path, dst_path)
