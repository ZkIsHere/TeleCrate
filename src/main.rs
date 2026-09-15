//! Binary `telecrate` — CLI + daemon dùng chung logic trong lib.
//! S3 API vẫn unsupported cho tới M2 — không mock 200.

use axum::{routing::get, Json, Router};
use clap::{Parser, Subcommand};
use serde_json::json;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "telecrate",
    version,
    about = "TeleCrate — S3-compatible storage on Telegram (single instance)"
)]
struct Cli {
    #[arg(long, default_value = "/etc/telecrate/telecrate.toml")]
    config: String,
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Khởi tạo thư mục state + config mẫu.
    Init,
    /// Chạy daemon HTTP (S3 + admin + dashboard tĩnh).
    Serve,
    /// Trạng thái thật: config + DB mở được.
    Status,
    /// Kiểm tra sức khỏe: config validate + migrations version.
    Doctor,
    /// Quản lý migrations: apply lên head (có backup DB trước khi apply).
    Migrations {
        #[command(subcommand)]
        op: MigOp,
    },
}

#[derive(Subcommand)]
enum MigOp {
    Apply,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
    let code = match run(cli).await {
        Ok(()) => 0,
        Err(e) => {
            // Không in secret — error không chứa secret (token luôn redact ở transport).
            eprintln!("telecrate: error: {e}");
            1
        }
    };
    std::process::exit(code);
}

async fn run(cli: Cli) -> Result<(), String> {
    match cli.cmd {
        Commands::Init => {
            println!("init: state dirs từ {}", cli.config);
            let cfg = telecrate::config::load(&cli.config).unwrap_or_default();
            std::fs::create_dir_all(&cfg.spool_dir)
                .map_err(|e| format!("create spool dir: {e}"))?;
            let mut conn = telecrate::db::open(&cfg.db_path)?;
            if telecrate::db::schema_version(&conn)? == 0 {
                telecrate::db::apply_migration(&mut conn, 1, telecrate::db::MIGRATION_001)?;
            }
            println!("init ok");
            Ok(())
        }
        Commands::Serve => {
            let cfg = telecrate::config::load(&cli.config)?;
            let app = Router::new()
                .route("/health", get(health))
                .route("/", get(index));
            let addr = format!("0.0.0.0:{}", cfg.listen_port);
            let listener = tokio::net::TcpListener::bind(&addr)
                .await
                .map_err(|e| format!("bind {addr}: {e}"))?;
            println!("telecrate serving on {addr}");
            axum::serve(listener, app)
                .await
                .map_err(|e| format!("serve: {e}"))?;
            Ok(())
        }
        Commands::Status => {
            let h = telecrate::health_check(&cli.config);
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": h.ok, "version": h.version, "detail": h.detail
                }))
                .unwrap()
            );
            if h.ok {
                Ok(())
            } else {
                Err(h.detail)
            }
        }
        Commands::Doctor => {
            let cfg = telecrate::config::load(&cli.config)?;
            let conn = telecrate::db::open(&cfg.db_path)?;
            let v = telecrate::db::schema_version(&conn)?;
            // Redaction: config hiện chưa có secret field nào (keys/secrets vào M2/M4).
            println!(
                "doctor ok: schema_version={v} spool={} db={}",
                cfg.spool_dir, cfg.db_path
            );
            Ok(())
        }
        Commands::Migrations { op } => match op {
            MigOp::Apply => {
                let cfg = telecrate::config::load(&cli.config)?;
                // Backup DB trước khi apply (M0: copy file sau checkpoint).
                let backup = format!("{}.pre-mig-backup", cfg.db_path);
                if std::path::Path::new(&cfg.db_path).exists() {
                    std::fs::copy(&cfg.db_path, &backup).map_err(|e| format!("backup db: {e}"))?;
                    println!("backup: {backup}");
                }
                let mut conn = telecrate::db::open(&cfg.db_path)?;
                if telecrate::db::schema_version(&conn)? == 0 {
                    telecrate::db::apply_migration(&mut conn, 1, telecrate::db::MIGRATION_001)?;
                }
                println!(
                    "migrations ok: version={}",
                    telecrate::db::schema_version(&conn)?
                );
                Ok(())
            }
        },
    }
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "ok": true, "version": telecrate::VERSION, "s3": "unsupported-m0" }))
}

async fn index() -> &'static str {
    "TeleCrate M0 bootstrap — dashboard đầy đủ ở M6."
}
