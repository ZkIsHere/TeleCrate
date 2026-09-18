//! CLI Client Module — TeleCrate M6.
//! Thực thi quy tắc kiến trúc: khi daemon đang RUNNING, CLI gửi lệnh qua Admin REST API/Socket
//! thay vì mở file SQLite trực tiếp để tránh tranh chấp khóa single-daemon.

use crate as telecrate;
use serde_json::json;

pub async fn is_daemon_running(config: &telecrate::config::Config) -> bool {
    let url = format!("http://127.0.0.1:{}/health", config.listen_port);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(1))
        .build();
    if let Ok(client) = client {
        if let Ok(resp) = client.get(&url).send().await {
            return resp.status().is_success();
        }
    }
    false
}

pub async fn run_status_cli(config_path: &str) -> Result<(), String> {
    let cfg = telecrate::config::load(config_path).unwrap_or_default();
    if is_daemon_running(&cfg).await {
        let url = format!("http://127.0.0.1:{}/admin/api/status", cfg.listen_port);
        let client = reqwest::Client::new();

        // Login first if admin_password configured
        let pwd = cfg.admin_password.as_deref().unwrap_or("telecrate-admin");
        let login_res = client
            .post(format!(
                "http://127.0.0.1:{}/admin/api/login",
                cfg.listen_port
            ))
            .json(&json!({ "password": pwd }))
            .send()
            .await;

        if let Ok(resp) = login_res {
            if resp.status().is_success() {
                let cookie = resp
                    .headers()
                    .get("set-cookie")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.split(';').next())
                    .unwrap_or("")
                    .to_string();

                if let Ok(status_resp) = client.get(&url).header("cookie", &cookie).send().await {
                    if let Ok(json_val) = status_resp.json::<serde_json::Value>().await {
                        println!(
                            "[DAEMON RUNNING]\n{}",
                            serde_json::to_string_pretty(&json_val).unwrap()
                        );
                        return Ok(());
                    }
                }
            }
        }
    }

    // Fallback standalone health check
    let h = telecrate::health_check(config_path);
    println!(
        "[DAEMON STOPPED]\n{}",
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

pub async fn run_gc_cli(config_path: &str) -> Result<(), String> {
    let cfg = telecrate::config::load(config_path)?;
    if is_daemon_running(&cfg).await {
        println!("--> Daemon đang chạy: Thực thi GC qua Admin REST API...");
        let client = reqwest::Client::new();
        let pwd = cfg.admin_password.as_deref().unwrap_or("telecrate-admin");

        let login_res = client
            .post(format!(
                "http://127.0.0.1:{}/admin/api/login",
                cfg.listen_port
            ))
            .json(&json!({ "password": pwd }))
            .send()
            .await
            .map_err(|e| format!("login failed: {e}"))?;

        let cookie = login_res
            .headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(';').next())
            .unwrap_or("")
            .to_string();

        let login_json: serde_json::Value = login_res.json().await.map_err(|e| e.to_string())?;
        let csrf_token = login_json["csrf_token"].as_str().unwrap_or_default();

        let gc_res = client
            .post(format!("http://127.0.0.1:{}/admin/api/gc", cfg.listen_port))
            .header("cookie", &cookie)
            .header("x-csrf-token", csrf_token)
            .send()
            .await
            .map_err(|e| format!("gc api failed: {e}"))?;

        let json_val: serde_json::Value = gc_res.json().await.map_err(|e| e.to_string())?;
        println!("{}", serde_json::to_string_pretty(&json_val).unwrap());
        return Ok(());
    }

    println!("--> Daemon đã dừng: Thực thi GC trực tiếp trên SQLite index...");
    let conn = telecrate::db::open(&cfg.db_path)?;
    let cfg_route = cfg.clone();
    let (transport, _) =
        tokio::task::spawn_blocking(move || (telecrate::app::build_transport(&cfg_route), ()))
            .await
            .map_err(|e| format!("build transport: {e}"))?;

    let stats = telecrate::gc::run_gc(
        &conn,
        std::path::Path::new(&cfg.spool_dir),
        transport
            .as_ref()
            .map(|t| t as &dyn telecrate::telegram::Transport),
    )?;

    println!("{}", serde_json::to_string_pretty(&stats).unwrap());
    Ok(())
}

pub async fn run_config_show_cli(config_path: &str) -> Result<(), String> {
    let cfg = telecrate::config::load(config_path)?;
    println!("{}", serde_json::to_string_pretty(&cfg).unwrap_or_default());
    Ok(())
}

pub async fn run_config_get_cli(config_path: &str, key: &str) -> Result<(), String> {
    let cfg = telecrate::config::load(config_path)?;
    let val = serde_json::to_value(&cfg).map_err(|e| e.to_string())?;
    if let Some(v) = val.get(key) {
        println!("{key} = {v}");
        Ok(())
    } else {
        Err(format!("Key '{key}' không tồn tại trong cấu hình"))
    }
}

pub async fn run_config_set_cli(config_path: &str, key: &str, val: &str) -> Result<(), String> {
    let mut cfg = telecrate::config::load(config_path)?;
    if is_daemon_running(&cfg).await {
        println!("--> Daemon đang chạy: Cập nhật config qua Admin REST API...");
        let client = reqwest::Client::new();
        let pwd = cfg.admin_password.as_deref().unwrap_or("telecrate-admin");

        let login_res = client
            .post(format!(
                "http://127.0.0.1:{}/admin/api/login",
                cfg.listen_port
            ))
            .json(&json!({ "password": pwd }))
            .send()
            .await
            .map_err(|e| format!("Login failed: {e}"))?;

        let cookie = login_res
            .headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(';').next())
            .unwrap_or("")
            .to_string();

        let json_body: serde_json::Value = login_res.json().await.map_err(|e| e.to_string())?;
        let csrf = json_body
            .get("csrf_token")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let resp = client
            .post(format!(
                "http://127.0.0.1:{}/admin/api/config",
                cfg.listen_port
            ))
            .header("cookie", &cookie)
            .header("x-csrf-token", csrf)
            .json(&json!({ "key": key, "value": val, "config_path": config_path }))
            .send()
            .await
            .map_err(|e| format!("API config update failed: {e}"))?;

        if resp.status().is_success() {
            println!("✅ Đã cập nhật '{key}' thành công trên Daemon và lưu vào {config_path}!");
            Ok(())
        } else {
            let err_body = resp.text().await.unwrap_or_default();
            Err(format!("API trả về lỗi: {err_body}"))
        }
    } else {
        println!("--> Daemon dừng: Cập nhật config trực tiếp file TOML...");
        cfg.update_key(key, val)?;
        cfg.save_to_file(config_path)?;
        // Không in secret/URL chứa password ra stdout.
        let shown = if key.contains("secret")
            || key.contains("password")
            || key.contains("token")
            || key.contains("database_url")
        {
            "[REDACTED]"
        } else {
            val
        };
        println!("✅ Đã cập nhật '{key}' = '{shown}' và lưu vào {config_path}!");
        Ok(())
    }
}
