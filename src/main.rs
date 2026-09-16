//! Binary `telecrate` — CLI + daemon dùng chung logic trong lib.
//! S3 buckets + SigV4 ở M2.1 (objects → 2.2) — không mock 200.

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "telecrate",
    version,
    about = "TeleCrate — S3-compatible storage on Telegram (single instance)"
)]
struct Cli {
    #[arg(long, global = true, default_value = "/etc/telecrate/telecrate.toml")]
    config: String,
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Khởi tạo thư mục state + config mẫu.
    Init,
    /// Chạy daemon HTTP (S3 + admin + dashboard tĩnh).
    #[command(alias = "daemon")]
    Serve,
    /// Trạng thái thật: config + DB mở được.
    Status,
    /// Kiểm tra sức khỏe: config validate, SQLite integrity check, migrations version.
    Doctor,
    /// Kiểm tra spool local (thiếu file, mồ côi, sai checksum).
    Verify,
    /// Scrubbing remote Telegram locators (tải/xác minh locator).
    Scrub,
    /// Thực thi Garbage Collection (dọn spool committed, delete messages Telegram đã xóa).
    Gc,
    /// Thao tác DB (backup/restore).
    Db {
        #[command(subcommand)]
        op: DbOp,
    },
    /// Standalone Recovery Bundle (export/import index metadata).
    Recovery {
        #[command(subcommand)]
        op: RecoveryOp,
    },
    /// Quản lý migrations: apply lên head (có backup DB trước khi apply).
    Migrations {
        #[command(subcommand)]
        op: MigOp,
    },
    /// Quản lý cấu hình động (show, get, set).
    Config {
        #[command(subcommand)]
        op: ConfigOp,
    },
}

#[derive(Subcommand)]
enum MigOp {
    Apply,
}

#[derive(Subcommand)]
enum ConfigOp {
    /// Hiển thị toàn bộ cấu hình hiện tại.
    Show,
    /// Lấy giá trị của một key cấu hình.
    Get { key: String },
    /// Cập nhật giá trị một key cấu hình (lưu file TOML, cập nhật live nếu daemon đang chạy).
    Set { key: String, value: String },
}

#[derive(Subcommand)]
enum DbOp {
    Backup {
        #[arg(short, long)]
        output: String,
        #[arg(short, long)]
        passphrase: Option<String>,
    },
    Restore {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        passphrase: Option<String>,
    },
}

#[derive(Subcommand)]
enum RecoveryOp {
    Export {
        #[arg(short, long)]
        output: String,
        #[arg(short, long)]
        passphrase: Option<String>,
    },
    Import {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        passphrase: Option<String>,
    },
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
            telecrate::db::apply_all_migrations(&mut conn)?;
            println!(
                "init ok: schema_version={}",
                telecrate::db::schema_version(&conn)?
            );
            Ok(())
        }
        Commands::Serve => {
            let cfg = telecrate::config::load(&cli.config)?;
            let mut conn = telecrate::db::open(&cfg.db_path)?;
            telecrate::db::apply_all_migrations(&mut conn)?;
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
            let config_lock = std::sync::Arc::new(std::sync::RwLock::new(cfg.clone()));
            let n = cfg.worker_concurrency;
            for i in 0..n {
                let db_path = cfg.db_path.clone();
                let sd = shutdown.clone();
                let cfg_lock = config_lock.clone();
                let owner = format!("serve-worker-{i}");
                std::thread::spawn(move || {
                    telecrate::worker::run_loop_dynamic(
                        &db_path,
                        cfg_lock,
                        owner,
                        std::time::Duration::from_secs(2),
                        sd,
                    );
                });
            }
            println!("worker: {n} luồng upload nền đang chạy (tự động nạp credentials)");

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
        Commands::Status => telecrate::cli::run_status_cli(&cli.config).await,
        Commands::Doctor => {
            let cfg = telecrate::config::load(&cli.config)?;
            let conn = telecrate::db::open(&cfg.db_path)?;
            let rep = telecrate::doctor::run_doctor(&conn)?;
            println!("{}", serde_json::to_string_pretty(&rep).unwrap());
            if rep.db_integrity_ok && rep.foreign_keys_ok {
                Ok(())
            } else {
                Err("doctor detected DB integrity issues".into())
            }
        }
        Commands::Verify => {
            let cfg = telecrate::config::load(&cli.config)?;
            let conn = telecrate::db::open(&cfg.db_path)?;
            let rep =
                telecrate::doctor::run_verify_spool(&conn, std::path::Path::new(&cfg.spool_dir))?;
            println!("{}", serde_json::to_string_pretty(&rep).unwrap());
            if rep.missing_spool_chunks.is_empty() && rep.corrupt_checksum_files.is_empty() {
                Ok(())
            } else {
                Err("verify detected missing or corrupt spool chunks".into())
            }
        }
        Commands::Scrub => {
            let cfg = telecrate::config::load(&cli.config)?;
            let conn = telecrate::db::open(&cfg.db_path)?;
            let cfg_route = cfg.clone();
            let (transport, _) = tokio::task::spawn_blocking(move || {
                (telecrate::app::build_transport(&cfg_route), ())
            })
            .await
            .map_err(|e| format!("build transport: {e}"))?;
            let tr = transport.ok_or("cannot scrub without configured telegram bot token")?;
            let rep = telecrate::doctor::run_scrub_remote(&conn, &tr)?;
            println!("{}", serde_json::to_string_pretty(&rep).unwrap());
            if rep.missing_or_corrupt_remote.is_empty() {
                Ok(())
            } else {
                Err("scrub detected unreachable remote chunks".into())
            }
        }
        Commands::Gc => telecrate::cli::run_gc_cli(&cli.config).await,
        Commands::Db { op } => match op {
            DbOp::Backup { output, passphrase } => {
                let cfg = telecrate::config::load(&cli.config)?;
                let conn = telecrate::db::open(&cfg.db_path)?;
                if let Some(pass) = passphrase {
                    telecrate::db::backup_db_encrypted(&conn, &output, &pass)?;
                    println!("db backup encrypted ok: {output}");
                } else {
                    telecrate::db::backup_db(&conn, &output)?;
                    println!("db backup plain ok: {output}");
                }
                Ok(())
            }
            DbOp::Restore { input, passphrase } => {
                let cfg = telecrate::config::load(&cli.config)?;
                telecrate::db::restore_db(&input, &cfg.db_path, passphrase.as_deref())?;
                println!("db restore ok: {}", cfg.db_path);
                Ok(())
            }
        },
        Commands::Recovery { op } => match op {
            RecoveryOp::Export { output, passphrase } => {
                let cfg = telecrate::config::load(&cli.config)?;
                let conn = telecrate::db::open(&cfg.db_path)?;
                telecrate::recovery::export_recovery_bundle_file(
                    &conn,
                    &output,
                    passphrase.as_deref(),
                )?;
                println!("recovery export ok: {output}");
                Ok(())
            }
            RecoveryOp::Import { input, passphrase } => {
                let cfg = telecrate::config::load(&cli.config)?;
                telecrate::recovery::import_recovery_bundle_file(
                    &input,
                    &cfg.db_path,
                    passphrase.as_deref(),
                )?;
                println!("recovery import ok: {}", cfg.db_path);
                Ok(())
            }
        },
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
                telecrate::db::apply_all_migrations(&mut conn)?;
                println!(
                    "migrations ok: version={}",
                    telecrate::db::schema_version(&conn)?
                );
                Ok(())
            }
        },
        Commands::Config { op } => match op {
            ConfigOp::Show => telecrate::cli::run_config_show_cli(&cli.config).await,
            ConfigOp::Get { key } => telecrate::cli::run_config_get_cli(&cli.config, &key).await,
            ConfigOp::Set { key, value } => {
                telecrate::cli::run_config_set_cli(&cli.config, &key, &value).await
            }
        },
    }
}
