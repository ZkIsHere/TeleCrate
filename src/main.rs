//! Binary `telecrate` — CLI + daemon dùng chung logic trong lib.
//! S3 buckets + SigV4 ở M2.1 (objects → 2.2) — không mock 200.

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
            let conn = telecrate::db::open(&cfg.db_path)?;
            let active_spools = telecrate::db::active_spool_paths(&conn).unwrap_or_default();
            let spool_dir = std::path::Path::new(&cfg.spool_dir);
            if let Ok((tmps, chunks)) = telecrate::spool::reconcile_spool(spool_dir, &active_spools)
            {
                if tmps > 0 || chunks > 0 {
                    println!("reconcile: đã dọn dẹp {tmps} tmp mồ côi, {chunks} chunk mồ côi");
                }
            }
            drop(conn);

            let addr = format!("0.0.0.0:{}", cfg.listen_port);
            let listener = tokio::net::TcpListener::bind(&addr)
                .await
                .map_err(|e| format!("bind {addr}: {e}"))?;
            println!("telecrate serving on {addr}");
            // Transport/keys dựng ngoài async context (spawn_blocking) —
            // dựng trực tiếp ở đây sẽ panic khi drop runtime nội bộ của reqwest.
            let cfg_route = cfg.clone();
            let (transport, keys) = tokio::task::spawn_blocking(move || {
                (
                    telecrate::app::build_transport(&cfg_route),
                    cfg_route.load_keystore(),
                )
            })
            .await
            .map_err(|e| format!("build transport/keys: {e}"))?;
            let keys = keys.map_err(|e| format!("content keys: {e}"))?;
            // Worker upload nền (M2.2): thread riêng + client blocking (ADR 0002).
            // Thiếu token/chat → worker idle, dữ liệu giữ ở spool (accepted-local).
            let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            if transport.is_some() {
                let n = cfg.worker_concurrency;
                for i in 0..n {
                    let worker_transport = transport.clone();
                    let db_path = cfg.db_path.clone();
                    let chat_id = cfg.telegram_chat_id;
                    let sd = shutdown.clone();
                    let owner = format!("serve-worker-{i}");
                    std::thread::spawn(move || {
                        telecrate::worker::run_loop(
                            &db_path,
                            worker_transport.as_ref().expect("checked above"),
                            chat_id,
                            owner,
                            std::time::Duration::from_secs(2),
                            sd,
                        );
                    });
                }
                println!("worker: {n} luồng upload nền đang chạy");
            } else {
                println!("worker: idle (chưa cấu hình telegram_bot_token/chat_id)");
            }
            let sd = shutdown.clone();
            axum::serve(listener, telecrate::app::router(cfg, transport, keys))
                .with_graceful_shutdown(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    sd.store(true, std::sync::atomic::Ordering::Relaxed);
                })
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
            // Chỉ in đường dẫn + version, không in nội dung config (có secrets từ M2.1).
            println!(
                "doctor ok: schema_version={v} spool={} db={}",
                cfg.spool_dir, cfg.db_path
            );
            Ok(())
        }
        Commands::Migrations { op } => match op {
            MigOp::Apply => {
                let cfg = telecrate::config::load(&cli.config)?;
                // Backup DB trước khi apply (copy file).
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
