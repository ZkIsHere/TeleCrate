//! Integration Test Suite cho Admin REST API & Web Dashboard M6.

use telecrate::config::Config;
use telecrate::crypto::KeyStore;
use tokio::net::TcpListener;

async fn spawn_test_app() -> (String, Config, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir
        .path()
        .join("telecrate.db")
        .to_str()
        .unwrap()
        .to_string();
    let spool_dir = dir.path().join("spool").to_str().unwrap().to_string();

    std::fs::create_dir_all(&spool_dir).unwrap();

    let mut conn = telecrate::db::open(&db_path).unwrap();
    telecrate::db::apply_all_migrations(&mut conn).unwrap();

    let config = Config {
        db_path,
        spool_dir,
        listen_port: 0,
        encryption: "off".to_string(),
        access_keys: Vec::new(),
        telegram_bot_token: "123456789:ABCdefGHIjklMNOpqrsTUVwxyz".to_string(),
        telegram_chat_id: -1001234567890,
        chunk_size_bytes: 8 * 1024 * 1024,
        worker_concurrency: 2,
        content_keys: Vec::new(),
        content_key_id: String::new(),
        admin_password: Some("test-admin-secret".to_string()),
        log_level: "info".to_string(),
        log_to_file: false,
        log_dir: "/tmp/telecrate-test-logs".to_string(),
        log_retention_days: 7,
    };

    let keys = KeyStore::load(&[]).unwrap();
    let router = telecrate::app::router(config.clone(), None, keys);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    (server_url, config, dir)
}

#[tokio::test]
async fn test_admin_dashboard_and_static_assets() {
    let (url, _cfg, _dir) = spawn_test_app().await;
    let client = reqwest::Client::new();

    // 1. GET / without Auth header -> returns HTML Web Dashboard
    let res = client.get(&url).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let body = res.text().await.unwrap();
    assert!(body.contains("TeleCrate"));

    // 2. GET /dashboard/style.css -> CSS
    let res_css = client
        .get(format!("{}/dashboard/style.css", url))
        .send()
        .await
        .unwrap();
    assert_eq!(res_css.status(), 200);
    let css_body = res_css.text().await.unwrap();
    assert!(css_body.contains("TeleCrate"));

    // 3. GET /dashboard/app.js -> JS
    let res_js = client
        .get(format!("{}/dashboard/app.js", url))
        .send()
        .await
        .unwrap();
    assert_eq!(res_js.status(), 200);
    let js_body = res_js.text().await.unwrap();
    assert!(js_body.contains("TeleCrate"));
}

#[tokio::test]
async fn test_admin_auth_session_and_csrf_flow() {
    let (url, _cfg, _dir) = spawn_test_app().await;
    let client = reqwest::Client::new();

    // 1. Session check initially unauthenticated
    let res_sess = client
        .get(format!("{}/admin/api/session", url))
        .send()
        .await
        .unwrap();
    assert_eq!(res_sess.status(), 200);
    let json_sess: serde_json::Value = res_sess.json().await.unwrap();
    assert_eq!(json_sess["authenticated"], false);

    // 2. Status without login -> 401
    let res_status_unauth = client
        .get(format!("{}/admin/api/status", url))
        .send()
        .await
        .unwrap();
    assert_eq!(res_status_unauth.status(), 401);

    // 3. Login with wrong password -> 401
    let res_login_fail = client
        .post(format!("{}/admin/api/login", url))
        .json(&serde_json::json!({ "password": "wrong-password" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res_login_fail.status(), 401);

    // 4. Login with correct password -> 200, returns Set-Cookie header
    let res_login_ok = client
        .post(format!("{}/admin/api/login", url))
        .json(&serde_json::json!({ "password": "test-admin-secret" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res_login_ok.status(), 200);

    let cookie_hdr = res_login_ok
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let session_cookie = cookie_hdr.split(';').next().unwrap().to_string();

    let login_json: serde_json::Value = res_login_ok.json().await.unwrap();
    assert_eq!(login_json["ok"], true);
    let csrf_token = login_json["csrf_token"].as_str().unwrap().to_string();
    assert!(!csrf_token.is_empty());

    // 5. Session check after login -> authenticated: true
    let res_sess_after = client
        .get(format!("{}/admin/api/session", url))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res_sess_after.status(), 200);
    let json_sess_after: serde_json::Value = res_sess_after.json().await.unwrap();
    assert_eq!(json_sess_after["authenticated"], true);
    assert_eq!(json_sess_after["csrf_token"], csrf_token);

    // 6. Get status -> 200
    let res_status = client
        .get(format!("{}/admin/api/status", url))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res_status.status(), 200);
    let status_json: serde_json::Value = res_status.json().await.unwrap();
    assert_eq!(status_json["version"], telecrate::VERSION);
    assert!(status_json["spool"]["total_bytes"].is_number());

    // 7. Create bucket without CSRF header -> 403 Forbidden
    let res_bkt_nocsrf = client
        .post(format!("{}/admin/api/buckets", url))
        .header("cookie", &session_cookie)
        .json(&serde_json::json!({ "name": "my-admin-bkt" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res_bkt_nocsrf.status(), 403);

    // 8. Create bucket with CSRF header -> 200 OK
    let res_bkt_ok = client
        .post(format!("{}/admin/api/buckets", url))
        .header("cookie", &session_cookie)
        .header("x-csrf-token", &csrf_token)
        .json(&serde_json::json!({ "name": "my-admin-bkt" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res_bkt_ok.status(), 200);

    // 9. List buckets -> 200
    let res_bkt_list = client
        .get(format!("{}/admin/api/buckets", url))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res_bkt_list.status(), 200);
    let bkts: Vec<serde_json::Value> = res_bkt_list.json().await.unwrap();
    assert_eq!(bkts.len(), 1);
    assert_eq!(bkts[0]["name"], "my-admin-bkt");

    // 10. Delete bucket -> 200
    let res_del_bkt = client
        .delete(format!("{}/admin/api/buckets/my-admin-bkt", url))
        .header("cookie", &session_cookie)
        .header("x-csrf-token", &csrf_token)
        .send()
        .await
        .unwrap();
    assert_eq!(res_del_bkt.status(), 200);

    // 11. Create Access Key -> 200
    let res_key_create = client
        .post(format!("{}/admin/api/access-keys", url))
        .header("cookie", &session_cookie)
        .header("x-csrf-token", &csrf_token)
        .json(&serde_json::json!({ "user_id": "test-user" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res_key_create.status(), 200);
    let key_json: serde_json::Value = res_key_create.json().await.unwrap();
    let access_key_id = key_json["access_key_id"].as_str().unwrap().to_string();
    assert!(access_key_id.starts_with("AKIA"));

    // 12. List Access Keys -> 200
    let res_keys_list = client
        .get(format!("{}/admin/api/access-keys", url))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res_keys_list.status(), 200);
    let keys: Vec<serde_json::Value> = res_keys_list.json().await.unwrap();
    assert_eq!(keys.len(), 1);

    // 13. Revoke Access Key -> 200
    let res_revoke = client
        .delete(format!("{}/admin/api/access-keys/{}", url, access_key_id))
        .header("cookie", &session_cookie)
        .header("x-csrf-token", &csrf_token)
        .send()
        .await
        .unwrap();
    assert_eq!(res_revoke.status(), 200);

    // 14. Trigger GC -> 200
    let res_gc = client
        .post(format!("{}/admin/api/gc", url))
        .header("cookie", &session_cookie)
        .header("x-csrf-token", &csrf_token)
        .send()
        .await
        .unwrap();
    assert_eq!(res_gc.status(), 200);

    // 15. Trigger Backup -> 200
    let res_backup = client
        .post(format!("{}/admin/api/backup", url))
        .header("cookie", &session_cookie)
        .header("x-csrf-token", &csrf_token)
        .send()
        .await
        .unwrap();
    assert_eq!(res_backup.status(), 200);

    // 16. Audit logs -> 200, shape {entries, total}, có bản ghi từ các bước trên
    let res_logs = client
        .get(format!("{}/admin/api/audit-logs", url))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res_logs.status(), 200);
    let logs_json: serde_json::Value = res_logs.json().await.unwrap();
    let entries = logs_json["entries"].as_array().unwrap();
    assert!(logs_json["total"].as_u64().unwrap() >= entries.len() as u64);
    assert!(entries.iter().any(|e| e["action"] == "bucket.create"));
    assert!(entries.iter().all(|e| e.get("ts").is_some()
        && e.get("level").is_some()
        && e.get("actor").is_some()
        && e.get("action").is_some()
        && e.get("detail").is_some()));

    // 16b. Lọc level=warn + phân trang limit=1.
    let res_warn = client
        .get(format!("{}/admin/api/audit-logs?level=warn&limit=1", url))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res_warn.status(), 200);
    let warn_json: serde_json::Value = res_warn.json().await.unwrap();
    for e in warn_json["entries"].as_array().unwrap() {
        assert_eq!(e["level"], "warn");
    }

    // 16c. level sai -> 400.
    let res_bad = client
        .get(format!("{}/admin/api/audit-logs?level=nope", url))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res_bad.status(), 400);

    // 17. Logout -> 200
    let res_logout = client
        .post(format!("{}/admin/api/logout", url))
        .header("cookie", &session_cookie)
        .header("x-csrf-token", &csrf_token)
        .send()
        .await
        .unwrap();
    assert_eq!(res_logout.status(), 200);

    // 18. Check session after logout -> authenticated: false
    let res_sess_end = client
        .get(format!("{}/admin/api/session", url))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    let json_end: serde_json::Value = res_sess_end.json().await.unwrap();
    assert_eq!(json_end["authenticated"], false);

    // 19. Rate-limit login: đã có 1 lần sai ở bước 3 → 9 lần nữa 401, rồi 429.
    for i in 0..11 {
        let r = client
            .post(format!("{}/admin/api/login", url))
            .json(&serde_json::json!({ "password": "wrong" }))
            .send()
            .await
            .unwrap();
        if i < 9 {
            assert_eq!(r.status(), 401, "lần {i}");
        } else {
            assert_eq!(r.status(), 429, "lần {i} phải bị rate-limit");
        }
    }
}
