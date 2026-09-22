//! Test parity schema: SeaORM entities phải khớp DDL thật cả hai backend (ADR 0006).
//!
//! - SQLite: apply migrations lên DB tạm, đọc `PRAGMA table_info`, đối chiếu với
//!   `CREATE TABLE` sinh từ entity bằng SeaQuery (Sqlite builder).
//! - Postgres: parse text `migrations/postgres/*.sql` (qua const
//!   `telecrate::db::POSTGRES_SCHEMA`: CREATE TABLE + ALTER TABLE ... ADD COLUMN),
//!   đối chiếu với `CREATE TABLE` sinh từ entity bằng SeaQuery (Postgres builder).
//!
//! So sánh theo tập cột + nhóm kiểu (int/text) — lệch tên/cột/thiếu cột là fail CI.

use sea_orm::{EntityName, EntityTrait, Schema};
use sea_query::{PostgresQueryBuilder, SqliteQueryBuilder};
use std::collections::{HashMap, HashSet};
use telecrate::db::entities::*;

type ColSet = HashMap<String, String>;

/// Chuẩn hóa tên cột: bỏ quote, lowercase.
fn norm_name(s: &str) -> String {
    s.trim()
        .trim_matches('"')
        .trim_matches('`')
        .trim_matches('[')
        .trim_matches(']')
        .to_ascii_lowercase()
}

/// Xếp kiểu khai báo vào nhóm để so sánh (`INTEGER` ~ `BIGINT`, `TEXT` ~ `VARCHAR`).
fn type_class(def: &str) -> Option<&'static str> {
    let d = def.to_ascii_lowercase();
    // "serial"/"bigserial" (SeaORM sinh cho identity trên Postgres) không chứa
    // chuỗi "int" nên phải liệt kê riêng.
    if d.contains("int") || d.contains("serial") {
        Some("int")
    } else if d.contains("text") || d.contains("char") || d.contains("clob") {
        Some("text")
    } else {
        None
    }
}

/// Tách các phần tử trong `(...)` theo dấu phẩy top-level (bỏ qua dấu phẩy trong
/// ngoặc — vd `to_char(..., 'YYYY-MM-DD HH24:MI:SS')` — và trong string literal).
fn split_top_level(body: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut in_str = false;
    let mut cur = String::new();
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if in_str {
            cur.push(c);
            if c == '\'' {
                if chars.peek() == Some(&'\'') {
                    cur.push(chars.next().unwrap());
                } else {
                    in_str = false;
                }
            }
            continue;
        }
        match c {
            '\'' => {
                in_str = true;
                cur.push(c);
            }
            '(' => {
                depth += 1;
                cur.push(c);
            }
            ')' => {
                depth = depth.saturating_sub(1);
                cur.push(c);
            }
            ',' if depth == 0 => {
                parts.push(cur);
                cur = String::new();
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        parts.push(cur);
    }
    parts
}

/// Parse `CREATE TABLE ... (...)` → (tên bảng, map cột → nhóm kiểu).
/// Bỏ qua constraint dòng (PRIMARY KEY / FOREIGN KEY / CONSTRAINT / UNIQUE / CHECK).
fn parse_create_table(sql: &str) -> Option<(String, ColSet)> {
    let low = sql.to_ascii_lowercase();
    let pos = low.find("create table")?;
    let mut rest = sql[pos + "create table".len()..].trim_start();
    if rest.to_ascii_lowercase().starts_with("if not exists") {
        rest = rest["if not exists".len()..].trim_start();
    }
    let name_end = rest
        .find(|c: char| c.is_whitespace() || c == '(')
        .unwrap_or(rest.len());
    let table = norm_name(&rest[..name_end]);
    let paren = rest.find('(')?;
    // Tìm dấu ')' cân bằng.
    let bytes = rest.as_bytes();
    let mut depth = 0usize;
    let mut end = None;
    let mut in_str = false;
    let mut i = paren;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if in_str {
            if c == '\'' {
                if i + 1 < bytes.len() && bytes[i + 1] as char == '\'' {
                    i += 1;
                } else {
                    in_str = false;
                }
            }
        } else if c == '\'' {
            in_str = true;
        } else if c == '(' {
            depth += 1;
        } else if c == ')' {
            depth -= 1;
            if depth == 0 {
                end = Some(i);
                break;
            }
        }
        i += 1;
    }
    let body = &rest[paren + 1..end?];
    let mut cols = ColSet::new();
    for part in split_top_level(body) {
        let p = part.trim();
        let pl = p.to_ascii_lowercase();
        if pl.starts_with("primary key")
            || pl.starts_with("foreign key")
            || pl.starts_with("constraint")
            || pl.starts_with("unique")
            || pl.starts_with("check")
        {
            continue;
        }
        let mut toks = p.split_whitespace();
        let name = match toks.next() {
            Some(n) => norm_name(n),
            None => continue,
        };
        if name.is_empty() {
            continue;
        }
        let def: String = toks.collect::<Vec<_>>().join(" ");
        if let Some(cls) = type_class(&def) {
            cols.insert(name, cls.to_string());
        }
    }
    Some((table, cols))
}

/// Parse toàn bộ text DDL Postgres: gom CREATE TABLE + ALTER TABLE ADD COLUMN.
fn parse_pg_ddl(text: &str) -> HashMap<String, ColSet> {
    let mut tables: HashMap<String, ColSet> = HashMap::new();
    for stmt in text.split(';') {
        // Bỏ comment dòng TRƯỚC khi xét (comment thường đứng đầu statement).
        let clean: String = stmt
            .lines()
            .filter(|l| !l.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n");
        if clean.trim().is_empty() {
            continue;
        }
        if clean.to_ascii_lowercase().contains("create table") {
            if let Some((t, cols)) = parse_create_table(&clean) {
                tables.entry(t).or_default().extend(cols);
            }
        } else if clean.to_ascii_lowercase().contains("drop table") {
            // DROP TABLE [IF EXISTS] <t> (migration dọn bảng chết).
            let toks: Vec<&str> = clean.split_whitespace().collect();
            if toks.len() >= 3
                && toks[0].eq_ignore_ascii_case("drop")
                && toks[1].eq_ignore_ascii_case("table")
            {
                // Bỏ qua IF [NOT] EXISTS (2-3 tokens) để tới tên bảng.
                let mut idx = 2;
                if toks
                    .get(idx)
                    .map(|t| t.eq_ignore_ascii_case("if"))
                    .unwrap_or(false)
                {
                    idx += 1;
                    if toks
                        .get(idx)
                        .map(|t| t.eq_ignore_ascii_case("not"))
                        .unwrap_or(false)
                    {
                        idx += 1;
                    }
                    if toks
                        .get(idx)
                        .map(|t| t.eq_ignore_ascii_case("exists"))
                        .unwrap_or(false)
                    {
                        idx += 1;
                    }
                }
                if let Some(t) = toks.get(idx) {
                    tables.remove(&norm_name(t.trim_end_matches(';')));
                }
            }
        } else if clean.to_ascii_lowercase().contains("alter table") {
            // ALTER TABLE <t> ADD COLUMN [IF NOT EXISTS] <col> <type...>
            //           <t> DROP COLUMN [IF EXISTS] <col>
            let toks: Vec<&str> = clean.split_whitespace().collect();
            if toks.len() >= 6
                && toks[0].eq_ignore_ascii_case("alter")
                && toks[1].eq_ignore_ascii_case("table")
                && toks[3].eq_ignore_ascii_case("drop")
            {
                let mut idx = 5; // sau DROP COLUMN (toks[4] == COLUMN)
                                 // Bỏ qua IF [NOT] EXISTS (PG: IF EXISTS; SQLite DROP COLUMN
                                 // không có mệnh đề này).
                if toks
                    .get(idx)
                    .map(|t| t.eq_ignore_ascii_case("if"))
                    .unwrap_or(false)
                {
                    idx += 1;
                    if toks
                        .get(idx)
                        .map(|t| t.eq_ignore_ascii_case("not"))
                        .unwrap_or(false)
                    {
                        idx += 1;
                    }
                    if toks
                        .get(idx)
                        .map(|t| t.eq_ignore_ascii_case("exists"))
                        .unwrap_or(false)
                    {
                        idx += 1;
                    }
                }
                if let Some(col) = toks.get(idx) {
                    if let Some(cols) = tables.get_mut(&norm_name(toks[2])) {
                        cols.remove(&norm_name(col.trim_matches('"').trim_end_matches(';')));
                    }
                }
            } else if toks.len() >= 6
                && toks[0].eq_ignore_ascii_case("alter")
                && toks[1].eq_ignore_ascii_case("table")
                && toks[3].eq_ignore_ascii_case("add")
            {
                let mut idx = 5; // sau ADD COLUMN (toks[4] == COLUMN)
                if toks
                    .get(idx)
                    .map(|t| t.eq_ignore_ascii_case("if"))
                    .unwrap_or(false)
                {
                    idx += 3; // IF NOT EXISTS
                }
                if let (Some(col), Some(typ)) = (toks.get(idx), toks.get(idx + 1)) {
                    if let Some(cls) = type_class(typ) {
                        tables
                            .entry(norm_name(toks[2]))
                            .or_default()
                            .insert(norm_name(col), cls.to_string());
                    }
                }
            }
        }
    }
    tables
}

fn entity_sqlite_cols<E: EntityTrait>() -> (String, ColSet) {
    let schema = Schema::new(sea_orm::DbBackend::Sqlite);
    let stmt = schema.create_table_from_entity(E::default());
    let sql = stmt.to_string(SqliteQueryBuilder);
    parse_create_table(&sql).expect("entity phai sinh duoc CREATE TABLE (sqlite)")
}

fn entity_pg_cols<E: EntityTrait>() -> (String, ColSet) {
    let schema = Schema::new(sea_orm::DbBackend::Postgres);
    let stmt = schema.create_table_from_entity(E::default());
    let sql = stmt.to_string(PostgresQueryBuilder);
    parse_create_table(&sql).expect("entity phai sinh duoc CREATE TABLE (postgres)")
}

fn assert_same(name: &str, backend: &str, entity_cols: &ColSet, real_cols: &ColSet) {
    let e: HashSet<_> = entity_cols.keys().collect();
    let r: HashSet<_> = real_cols.keys().collect();
    let missing: Vec<_> = e.difference(&r).collect();
    let extra: Vec<_> = r.difference(&e).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "lech cot bang '{name}' ({backend}): thieu trong DDL that={missing:?}, thua trong DDL that={extra:?}"
    );
    for (col, cls) in entity_cols {
        assert_eq!(
            real_cols.get(col).map(String::as_str),
            Some(cls.as_str()),
            "lech kieu cot '{name}.{col}' ({backend}): entity={cls}, ddl={:?}",
            real_cols.get(col),
        );
    }
}

fn check_sqlite<E: EntityTrait>(real: &HashMap<String, ColSet>) {
    let (table, cols) = entity_sqlite_cols::<E>();
    // Tên bảng entity phải trùng tên bảng DDL (phát hiện sai table_name!).
    let ddl_cols = real
        .get(&table)
        .unwrap_or_else(|| panic!("entity sinh bang '{table}' khong co trong DDL sqlite"));
    assert_same(&table, "sqlite", &cols, ddl_cols);
}

fn check_pg<E: EntityTrait>(real: &HashMap<String, ColSet>) {
    let (table, cols) = entity_pg_cols::<E>();
    let ddl_cols = real
        .get(&table)
        .unwrap_or_else(|| panic!("entity sinh bang '{table}' khong co trong DDL postgres"));
    assert_same(&table, "postgres", &cols, ddl_cols);
}

/// Đối chiếu tên bảng hai phía (entity ↔ DDL) để không sót/thừa bảng nào.
fn assert_table_sets(
    entity_tables: &HashSet<String>,
    real: &HashMap<String, ColSet>,
    backend: &str,
) {
    let r: HashSet<String> = real.keys().cloned().collect();
    assert_eq!(
        entity_tables, &r,
        "lech tap bang ({backend}): entity={entity_tables:?} ddl={r:?}"
    );
}

#[tokio::test]
async fn test_entity_parity_sqlite_applied_schema() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("parity.db");
    let db = telecrate::db::Db::open_sqlite(db_path.to_str().unwrap())
        .await
        .unwrap();
    telecrate::db::apply_all_migrations(&db).await.unwrap();

    // Đọc schema thật sau migrate (qua sea Statement — PRAGMA là intrinsic).
    use sea_orm::{ConnectionTrait, Statement};
    let conn = db.sea_conn();
    let rows = conn
        .query_all(Statement::from_string(
            sea_orm::DbBackend::Sqlite,
            "SELECT name AS name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'".to_string(),
        ))
        .await
        .unwrap();
    let mut real: HashMap<String, ColSet> = HashMap::new();
    for r in rows {
        let t: String = r.try_get("", "name").unwrap();
        let info = conn
            .query_all(Statement::from_string(
                sea_orm::DbBackend::Sqlite,
                format!("PRAGMA table_info(\"{t}\")"),
            ))
            .await
            .unwrap();
        let mut cols = ColSet::new();
        for c in info {
            let name: String = c.try_get("", "name").unwrap();
            let typ: String = c.try_get("", "type").unwrap_or_default();
            if let Some(cls) = type_class(&typ) {
                cols.insert(norm_name(&name), cls.to_string());
            }
        }
        real.insert(t, cols);
    }

    macro_rules! run {
        ($($ent:ty),+) => {{
            $( check_sqlite::<$ent>(&real); )+
            let mut set = HashSet::new();
            $( set.insert(<$ent as EntityName>::table_name(&<$ent as Default>::default()).to_string()); )+
            assert_table_sets(&set, &real, "sqlite");
        }};
    }
    run!(
        schema_version::Entity,
        buckets::Entity,
        objects::Entity,
        chunks::Entity,
        upload_jobs::Entity,
        multipart_uploads::Entity,
        multipart_parts::Entity,
        access_keys::Entity,
        bucket_policies::Entity,
        bucket_cors::Entity,
        bucket_bpa::Entity,
        bucket_lock_configs::Entity,
        object_locks::Entity
    );
}

#[test]
fn test_entity_parity_postgres_ddl_text() {
    let real = parse_pg_ddl(telecrate::db::POSTGRES_SCHEMA);
    macro_rules! run {
        ($($ent:ty),+) => {{
            $( check_pg::<$ent>(&real); )+
            let mut set = HashSet::new();
            $( set.insert(<$ent as EntityName>::table_name(&<$ent as Default>::default()).to_string()); )+
            assert_table_sets(&set, &real, "postgres");
        }};
    }
    run!(
        schema_version::Entity,
        buckets::Entity,
        objects::Entity,
        chunks::Entity,
        upload_jobs::Entity,
        multipart_uploads::Entity,
        multipart_parts::Entity,
        access_keys::Entity,
        bucket_policies::Entity,
        bucket_cors::Entity,
        bucket_bpa::Entity,
        bucket_lock_configs::Entity,
        object_locks::Entity
    );
}
