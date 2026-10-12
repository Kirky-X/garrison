// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! TLS 证书文件进程内热重载（feature = "tls-cert-watch"）。
//!
//! confers `MultiFsWatcher` 监视证书与私钥文件（文件目标经父目录 + 精确路径过滤，兼容
//! 「原地覆盖写」与「写临时文件 + 原子重命名」两种换证手法），去抖后的变更事件驱动
//! [`RustlsConfig::reload_from_pem_file`] 换入新配置：RustlsConfig 内部为 ArcSwap，
//! 每连接握手时读取最新快照，故换证不中断既有连接、无需重启进程。解析失败时不换入
//! （换入仅在解析成功后发生），旧证书继续服务：失败原因记 error，等下一次文件事件再试。

use std::path::{Path, PathBuf};

use axum_server::tls_rustls::RustlsConfig;
use confers::watcher::MultiFsWatcher;

/// 证书文件变更去抖窗口（毫秒）：覆盖覆盖写与「写临时文件 + rename」产生的连续事件，
/// 使重载读到的是写完后的完整 PEM 而非半写中间态。
const CERT_WATCH_DEBOUNCE_MS: u64 = 200;

/// 按路径当前内容重载一次共享 TLS 配置。
///
/// 返回 `Err` 时配置未被换入（旧证书继续服务），调用方据返回值决定日志级别
/// （watcher 循环记 error 后等下一次事件，不中断服务）。
pub(super) async fn reload_from_paths(
    config: &RustlsConfig,
    cert_path: &Path,
    key_path: &Path,
) -> Result<(), String> {
    config
        .reload_from_pem_file(cert_path, key_path)
        .await
        .map_err(|e| e.to_string())
}

/// 归一化监视/重载路径：父目录取 canonical（展开符号链接前缀），文件名原样保留。
///
/// 必要性：`MultiFsWatcher` 用 `path.parent()` 作监视根、按「调用方路径与事件路径逐字相等」
/// 过滤，而 notify-debouncer-full 先 canonicalize 监视根再拼接事件路径——相对路径或含
/// 符号链接前缀的路径永不匹配，watcher 保持运行却静默不再重载（上游 `FsWatcher` 内部
/// 对同一失效模式已做绝对化，`MultiFsWatcher` 未做）。文件名不参与 canonicalize：
/// 叶子为符号链接时监视的是目录项本身（链接重指向可被捕获），重载按原路径读取并跟随链接。
fn normalized_watch_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    let (parent, file_name) = match (absolute.parent(), absolute.file_name()) {
        (Some(parent), Some(file_name)) => (parent, file_name),
        _ => return absolute,
    };
    std::fs::canonicalize(parent)
        .map(|canonical_parent| canonical_parent.join(file_name))
        .unwrap_or(absolute)
}

/// 启动证书热重载任务，返回句柄供调用方在服务退出时 abort。
///
/// 监视线程无法建立（路径缺失/不可监视）时热重载能力显式丧失：记 error 后任务退出；
/// watcher 线程中途退出（`recv()` 返回 `None`）时记 warn 后退出，不静默失去重载能力。
/// `shutdown` 触发后任务退出，语义与两条 serve 任务一致。
pub(super) fn spawn_cert_watcher(
    config: RustlsConfig,
    cert_path: PathBuf,
    key_path: PathBuf,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let cert_path = normalized_watch_path(&cert_path);
        let key_path = normalized_watch_path(&key_path);
        let paths = [cert_path.as_path(), key_path.as_path()];
        let mut watcher = match MultiFsWatcher::new(paths, CERT_WATCH_DEBOUNCE_MS).await {
            Ok(watcher) => watcher,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    cert = %cert_path.display(),
                    key = %key_path.display(),
                    "tls cert watcher start failed; certificate hot reload disabled"
                );
                return;
            },
        };
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                event = watcher.recv() => match event {
                    Some(changed) => {
                        match reload_from_paths(&config, &cert_path, &key_path).await {
                            Ok(()) => tracing::info!(
                                changed = %changed.display(),
                                "tls certificate reloaded after file change"
                            ),
                            Err(e) => tracing::error!(
                                error = %e,
                                "tls certificate reload failed; keeping the previous certificate"
                            ),
                        }
                    },
                    None => {
                        tracing::warn!(
                            "tls cert watcher stopped; certificate hot reload no longer available"
                        );
                        break;
                    },
                },
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{AuthBackend, BackendEmbedded};
    use crate::server::GarrisonAuthServer;
    use axum::routing::get;
    use axum::Router;
    use std::sync::Arc;

    /// 测试用 CA：自签根证书 + 由其签发服务器证书（SAN = 127.0.0.1，供回环握手）。
    struct TestCa {
        /// 根证书 PEM（客户端信任锚）。
        ca_pem: String,
        params: rcgen::CertificateParams,
        key: rcgen::KeyPair,
    }

    impl TestCa {
        fn new(common_name: &str) -> Self {
            let mut params = rcgen::CertificateParams::new(Vec::new()).expect("CA 参数应构建成功");
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, common_name);
            let key = rcgen::KeyPair::generate().expect("CA 密钥应生成成功");
            let cert = params.self_signed(&key).expect("CA 证书应自签成功");
            Self {
                ca_pem: cert.pem(),
                params,
                key,
            }
        }

        /// 签发服务器证书与私钥（PEM 对）。
        fn issue_server_cert(&self) -> (String, String) {
            let mut params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
                .expect("服务器证书参数应构建成功");
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "127.0.0.1");
            let key = rcgen::KeyPair::generate().expect("服务器密钥应生成成功");
            let issuer = rcgen::Issuer::from_params(&self.params, &self.key);
            let cert = params
                .signed_by(&key, &issuer)
                .expect("服务器证书应签发成功");
            (cert.pem(), key.serialize_pem())
        }
    }

    /// 安装进程级 rustls CryptoProvider（与生产依赖图一致的 aws-lc-rs）：
    /// lib 测试图里 rustls 同时被启用 `aws-lc-rs` 与 `ring`（见 Cargo.toml dev-deps 注释），
    /// 不显式安装则 axum-server 构造 `ServerConfig` 时 panic；幂等，重复调用无副作用。
    fn install_crypto_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    /// 以 `ca_pem` 为唯一信任锚的 HTTPS 客户端：不合并平台根证书，握手成败即锚定关系判定。
    fn client_trusting(ca_pem: &str) -> reqwest::Client {
        let ca = reqwest::Certificate::from_pem(ca_pem.as_bytes()).expect("CA 证书应解析成功");
        reqwest::Client::builder()
            .use_rustls_tls()
            .tls_certs_only([ca])
            .build()
            .expect("客户端应构建成功")
    }

    /// `reqwest::Error` 的 source 链文本（诊断输出 + 失败原因断言用）。
    fn error_chain(err: &reqwest::Error) -> String {
        let mut parts = vec![err.to_string()];
        let mut cur = std::error::Error::source(err);
        while let Some(e) = cur {
            parts.push(e.to_string());
            cur = e.source();
        }
        parts.join(" | ")
    }

    /// 在回环随机端口启动 TLS 终止的 axum 服务器，返回端口与任务句柄。
    async fn spawn_tls_server(
        config: RustlsConfig,
    ) -> (u16, tokio::task::JoinHandle<std::io::Result<()>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("绑定回环端口应成功");
        let port = listener.local_addr().expect("读取本地端口应成功").port();
        // tokio → std：into_std 保留非阻塞标志，from_tcp_rustls 拒绝阻塞 socket
        let listener = listener.into_std().expect("转换 std 监听器应成功");
        let app = Router::new().route("/", get(|| async { "tls-ok" }));
        let server = axum_server::from_tcp_rustls(listener, config).expect("TLS 服务器应构建成功");
        (port, tokio::spawn(server.serve(app.into_make_service())))
    }

    /// 取一个当前空闲的回环端口（用于 `listen()` 绑定，测试内独占使用）。
    fn free_loopback_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("绑定回环端口应成功")
            .local_addr()
            .expect("读取本地端口应成功")
            .port()
    }

    /// 外网探针：`POST /api/v1/auth/login`，返回状态码（外网 login 默认关闭时应为 404）。
    async fn external_login_status(
        client: &reqwest::Client,
        url: &str,
        body: &str,
    ) -> reqwest::Result<u16> {
        client
            .post(url)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map(|resp| resp.status().as_u16())
    }

    /// 内网探针：`GET /api/v1/auth/health`（携有效 API Key，避免触发失败锁定），返回状态码与 `data` 字段。
    async fn internal_health(
        client: &reqwest::Client,
        url: &str,
        api_key: &str,
    ) -> reqwest::Result<(u16, String)> {
        let resp = client.get(url).header("x-api-key", api_key).send().await?;
        let status = resp.status().as_u16();
        let body = resp.text().await?;
        let data = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("data").and_then(|d| d.as_str()).map(str::to_string))
            .unwrap_or_default();
        Ok((status, data))
    }

    /// 写入证书/私钥到临时目录，返回（目录，证书路径，私钥路径）。
    fn write_pem_pair(dir: &std::path::Path, cert_pem: &str, key_pem: &str) -> (PathBuf, PathBuf) {
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert_pem).expect("写证书应成功");
        std::fs::write(&key_path, key_pem).expect("写私钥应成功");
        (cert_path, key_path)
    }

    /// 重载失败保留旧证书：非法/半写 PEM 返回显式错误且配置未被换入；写入合法 PEM 后换入成功。
    #[tokio::test]
    async fn reload_failure_keeps_previous_certificate() {
        install_crypto_provider();
        let ca1 = TestCa::new("garrison-test-ca-keep-old");
        let ca2 = TestCa::new("garrison-test-ca-swap-new");
        let (cert1, key1) = ca1.issue_server_cert();
        let (cert2, key2) = ca2.issue_server_cert();

        let dir = tempfile::tempdir().expect("临时目录应创建成功");
        let (cert_path, key_path) = write_pem_pair(dir.path(), &cert1, &key1);
        let config = RustlsConfig::from_pem_file(&cert_path, &key_path)
            .await
            .expect("初始证书应加载成功");
        let before = config.get_inner();

        // 半写中间态：base64 段不是合法 DER 证书
        std::fs::write(
            &cert_path,
            "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n",
        )
        .expect("写非法证书应成功");
        let err = reload_from_paths(&config, &cert_path, &key_path)
            .await
            .expect_err("非法 PEM 应返回错误");
        assert!(
            err.contains("certificate"),
            "错误应显式携带底层解析原因，实际: {err}"
        );
        assert!(
            Arc::ptr_eq(&before, &config.get_inner()),
            "重载失败必须保留旧配置（未换入）"
        );

        // 写入合法新证书：换入发生（新快照替换旧快照）
        std::fs::write(&cert_path, &cert2).expect("改写证书应成功");
        std::fs::write(&key_path, &key2).expect("改写私钥应成功");
        reload_from_paths(&config, &cert_path, &key_path)
            .await
            .expect("合法 PEM 应换入成功");
        assert!(
            !Arc::ptr_eq(&before, &config.get_inner()),
            "换入成功后配置快照应被替换"
        );
    }

    /// 换证端到端：watcher 去抖后新握手使用新证书，旧信任锚被拒。
    #[tokio::test]
    async fn watcher_rotation_switches_served_certificate() {
        install_crypto_provider();
        let ca1 = TestCa::new("garrison-test-ca-before");
        let ca2 = TestCa::new("garrison-test-ca-after");
        let (cert1, key1) = ca1.issue_server_cert();
        let (cert2, key2) = ca2.issue_server_cert();

        let dir = tempfile::tempdir().expect("临时目录应创建成功");
        let (cert_path, key_path) = write_pem_pair(dir.path(), &cert1, &key1);
        let config = RustlsConfig::from_pem_file(&cert_path, &key_path)
            .await
            .expect("初始证书应加载成功");
        let (port, server) = spawn_tls_server(config.clone()).await;
        let watcher = spawn_cert_watcher(
            config,
            cert_path.clone(),
            key_path.clone(),
            std::future::pending(),
        );

        let url = format!("https://127.0.0.1:{port}/");
        let ca1_client = client_trusting(&ca1.ca_pem);
        let ca2_client = client_trusting(&ca2.ca_pem);

        let first = ca1_client
            .get(&url)
            .send()
            .await
            .expect("换证前 CA1 客户端应握手成功");
        assert_eq!(first.status(), 200);
        assert_eq!(first.text().await.unwrap(), "tls-ok");
        assert!(
            ca2_client.get(&url).send().await.is_err(),
            "换证前 CA1 之外的信任锚不应被接受"
        );

        // 原地改写证书与私钥（同一路径）：watcher 捕获变更并去抖后重载
        std::fs::write(&cert_path, &cert2).expect("改写证书应成功");
        std::fs::write(&key_path, &key2).expect("改写私钥应成功");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut swapped = false;
        while std::time::Instant::now() < deadline {
            if ca2_client.get(&url).send().await.is_ok() {
                swapped = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(swapped, "watcher 去抖后应换入 CA2 签发的证书");

        // 换证只影响新握手：既有连接与客户端会话缓存仍属旧证书语义，
        // 故换证后的锚定判定必须用新建客户端发起全新握手。
        let ca1_after = client_trusting(&ca1.ca_pem);
        let err = ca1_after
            .get(&url)
            .send()
            .await
            .expect_err("换证后 CA1 客户端应握手失败");
        let chain = error_chain(&err);
        assert!(
            chain.contains("UnknownIssuer"),
            "CA1 失败原因应为证书链不受信任（UnknownIssuer），实际: {chain}"
        );
        let ca2_after = client_trusting(&ca2.ca_pem);
        let after = ca2_after
            .get(&url)
            .send()
            .await
            .expect("换证后 CA2 客户端应握手成功");
        assert_eq!(after.status(), 200);
        assert_eq!(after.text().await.unwrap(), "tls-ok");

        watcher.abort();
        server.abort();
    }

    /// 相对路径下换证仍会触发重载：confers `MultiFsWatcher` 按「调用方路径与事件路径逐字相等」
    /// 过滤，而事件路径基于 canonical 监视根拼接——未绝对化的相对路径永不匹配即静默空转。
    #[tokio::test]
    async fn watcher_reloads_with_relative_device_paths() {
        install_crypto_provider();
        let ca1 = TestCa::new("garrison-test-ca-relative-before");
        let ca2 = TestCa::new("garrison-test-ca-relative-after");
        let (cert1, key1) = ca1.issue_server_cert();
        let (cert2, key2) = ca2.issue_server_cert();

        // cargo test 的 CWD 为 crate 根；tempfile 内部会把路径绝对化，故取回相对形式以覆盖相对路径场景
        let dir = tempfile::Builder::new()
            .prefix("garrison-tls-relative-")
            .tempdir_in(".")
            .expect("在 crate 根创建临时目录应成功");
        let cwd = std::env::current_dir().expect("读取当前目录应成功");
        let relative_dir = dir
            .path()
            .strip_prefix(&cwd)
            .expect("临时目录应位于 crate 根下")
            .to_path_buf();
        let (cert_path, key_path) = write_pem_pair(&relative_dir, &cert1, &key1);
        assert!(
            cert_path.is_relative(),
            "测试前提：证书路径应为相对路径，实际: {}",
            cert_path.display()
        );

        let config = RustlsConfig::from_pem_file(&cert_path, &key_path)
            .await
            .expect("初始证书应加载成功");
        let (port, server) = spawn_tls_server(config.clone()).await;
        let watcher = spawn_cert_watcher(
            config,
            cert_path.clone(),
            key_path.clone(),
            std::future::pending(),
        );

        let url = format!("https://127.0.0.1:{port}/");
        let ca1_client = client_trusting(&ca1.ca_pem);
        let ca2_client = client_trusting(&ca2.ca_pem);
        assert_eq!(
            ca1_client
                .get(&url)
                .send()
                .await
                .expect("换证前 CA1 客户端应握手成功")
                .status(),
            200
        );

        std::fs::write(&cert_path, &cert2).expect("改写证书应成功");
        std::fs::write(&key_path, &key2).expect("改写私钥应成功");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut swapped = false;
        while std::time::Instant::now() < deadline {
            if ca2_client.get(&url).send().await.is_ok() {
                swapped = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(swapped, "相对路径下 watcher 去抖后应换入 CA2 签发的证书");

        watcher.abort();
        server.abort();
    }

    /// 证书/私钥路径为符号链接、换证以「重指向链接」完成时仍会重载：监视父目录 + 按原路径
    /// 读取，故叶子链接的重指向（证书管理工具的常见手法）也被事件过滤放行。
    #[cfg(unix)]
    #[tokio::test]
    async fn watcher_reloads_when_device_paths_are_symlinks() {
        install_crypto_provider();
        let ca1 = TestCa::new("garrison-test-ca-symlink-before");
        let ca2 = TestCa::new("garrison-test-ca-symlink-after");
        let (cert1, key1) = ca1.issue_server_cert();
        let (cert2, key2) = ca2.issue_server_cert();

        let dir = tempfile::tempdir().expect("临时目录应创建成功");
        let v1 = dir.path().join("v1");
        let v2 = dir.path().join("v2");
        std::fs::create_dir(&v1).expect("创建 v1 应成功");
        std::fs::create_dir(&v2).expect("创建 v2 应成功");
        let (cert_v1, key_v1) = write_pem_pair(&v1, &cert1, &key1);
        let (cert_v2, key_v2) = write_pem_pair(&v2, &cert2, &key2);

        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::os::unix::fs::symlink(&cert_v1, &cert_path).expect("创建证书符号链接应成功");
        std::os::unix::fs::symlink(&key_v1, &key_path).expect("创建私钥符号链接应成功");

        let config = RustlsConfig::from_pem_file(&cert_path, &key_path)
            .await
            .expect("初始证书应加载成功");
        let (port, server) = spawn_tls_server(config.clone()).await;
        let watcher = spawn_cert_watcher(
            config,
            cert_path.clone(),
            key_path.clone(),
            std::future::pending(),
        );

        let url = format!("https://127.0.0.1:{port}/");
        let ca1_client = client_trusting(&ca1.ca_pem);
        let ca2_client = client_trusting(&ca2.ca_pem);
        assert_eq!(
            ca1_client
                .get(&url)
                .send()
                .await
                .expect("换证前 CA1 客户端应握手成功")
                .status(),
            200
        );

        // 写临时链接 + rename 覆盖：与证书管理工具重指向符号链接的手法一致
        let tmp_cert = dir.path().join("cert.pem.new");
        let tmp_key = dir.path().join("key.pem.new");
        std::os::unix::fs::symlink(&cert_v2, &tmp_cert).expect("创建新证书链接应成功");
        std::os::unix::fs::symlink(&key_v2, &tmp_key).expect("创建新私钥链接应成功");
        std::fs::rename(&tmp_cert, &cert_path).expect("覆盖证书链接应成功");
        std::fs::rename(&tmp_key, &key_path).expect("覆盖私钥链接应成功");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut swapped = false;
        while std::time::Instant::now() < deadline {
            if ca2_client.get(&url).send().await.is_ok() {
                swapped = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(
            swapped,
            "符号链接重指向后 watcher 去抖后应换入 CA2 签发的证书"
        );

        watcher.abort();
        server.abort();
    }

    /// 监视路径缺失时热重载能力显式丧失：watcher 任务记 error 后自行退出，不悬挂。
    #[tokio::test]
    async fn watcher_exits_when_paths_unwatchable() {
        install_crypto_provider();
        let ca = TestCa::new("garrison-test-ca-unwatchable");
        let (cert, key) = ca.issue_server_cert();
        let dir = tempfile::tempdir().expect("临时目录应创建成功");
        let (cert_path, key_path) = write_pem_pair(dir.path(), &cert, &key);
        let config = RustlsConfig::from_pem_file(&cert_path, &key_path)
            .await
            .expect("初始证书应加载成功");

        std::fs::remove_file(&cert_path).expect("删除证书文件应成功");
        let handle = spawn_cert_watcher(config, cert_path, key_path, std::future::pending());
        tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("监视路径缺失时 watcher 任务应自行退出而非悬挂")
            .expect("watcher 任务不应 panic");
    }

    /// `listen()` 接线：两端口共用同一 TLS 配置，换证后两端口新握手同时切换；
    /// 既有契约在 TLS 路径不变（外网 login 默认 404、内网 health 缺 API Key 401 / 持有效 key 200）。
    #[tokio::test]
    async fn listen_serves_both_ports_and_hot_reloads_certificate() {
        install_crypto_provider();
        let ca1 = TestCa::new("garrison-test-ca-listen-before");
        let ca2 = TestCa::new("garrison-test-ca-listen-after");
        let (cert1, key1) = ca1.issue_server_cert();
        let (cert2, key2) = ca2.issue_server_cert();

        let dir = tempfile::tempdir().expect("临时目录应创建成功");
        let (cert_path, key_path) = write_pem_pair(dir.path(), &cert1, &key1);

        let external_port = free_loopback_port();
        let internal_port = free_loopback_port();
        let api_key = "test-api-key-aaaaaaaaaaaaaaaaaaaaaaaaaa";
        let backend: Arc<dyn AuthBackend> = Arc::new(BackendEmbedded::new());
        let server = GarrisonAuthServer::new(backend)
            .with_external_port(external_port)
            .with_external_bind(std::net::IpAddr::from([127, 0, 0, 1]))
            .with_internal_port(internal_port)
            .with_internal_bind(std::net::IpAddr::from([127, 0, 0, 1]))
            .with_internal_api_key(api_key)
            .with_tls(&cert_path, &key_path);
        let listen = tokio::spawn(server.listen());

        let external_url = format!("https://127.0.0.1:{external_port}/api/v1/auth/login");
        let internal_url = format!("https://127.0.0.1:{internal_port}/api/v1/auth/health");
        let login_body = serde_json::json!({
            "login_id": "probe-user",
            "params": crate::backend::types::LoginParams::default()
        })
        .to_string();
        let ca1_client = client_trusting(&ca1.ca_pem);
        let ca2_client = client_trusting(&ca2.ca_pem);

        // 两端口握手就绪（listen 内部为每个端口独立 task，绑定完成时间不确定）
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            assert!(
                std::time::Instant::now() < deadline,
                "listen() 后两个 TLS 端口应在超时内就绪"
            );
            if matches!(
                external_login_status(&ca1_client, &external_url, &login_body).await,
                Ok(404)
            ) {
                // 外网 login 默认关闭时的 404 契约在 TLS 路径不变
                if let Ok((200, data)) = internal_health(&ca1_client, &internal_url, api_key).await
                {
                    assert_eq!(data, "ok", "内网 health 应返回 data=ok");
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(
            external_login_status(&ca2_client, &external_url, &login_body)
                .await
                .is_err(),
            "换证前 CA1 之外的信任锚不应被接受"
        );

        // 改写证书文件：watcher 重载共享配置，两端口同时换用新证书
        std::fs::write(&cert_path, &cert2).expect("改写证书应成功");
        std::fs::write(&key_path, &key2).expect("改写私钥应成功");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut swapped = false;
        while std::time::Instant::now() < deadline {
            if matches!(
                external_login_status(&ca2_client, &external_url, &login_body).await,
                Ok(404)
            ) && matches!(
                internal_health(&ca2_client, &internal_url, api_key).await,
                Ok((200, _))
            ) {
                swapped = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(swapped, "去抖后两端口应换用 CA2 签发的证书");
        // 换证只影响新握手：用新建客户端（无既有连接/会话缓存）断言旧锚在两个端口均被拒
        let ca1_after = client_trusting(&ca1.ca_pem);
        assert!(
            external_login_status(&ca1_after, &external_url, &login_body)
                .await
                .is_err(),
            "换证后旧信任锚在外网端口应被拒"
        );
        assert!(
            internal_health(&ca1_after, &internal_url, api_key)
                .await
                .is_err(),
            "换证后旧信任锚在内网端口应被拒"
        );
        assert!(
            !listen.is_finished(),
            "listen() 任务不应在测试期间结束（两端口应持续服务）"
        );

        listen.abort();
    }
}
