// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `garrison-cli`——独立运维工具 bin。
//!
//! 与 `auth_server` / `garrison-healthcheck` 的零依赖立场不同，本 bin 门控在
//! `cli-ops` feature 后（clap 派生 API），**不进入默认容器镜像**——两个
//! Dockerfile 的 build 目标只有 `auth_server` 与 `garrison-healthcheck`，
//! 主镜像零依赖决策不受影响。
//!
//! # 子命令
//!
//! - `healthcheck`：对 127.0.0.1:{port}/healthz 执行存活探测（与
//!   `garrison-healthcheck` 探针共用同一纯 std 判定函数，见
//!   `garrison::health::probe`）
//! - `key-rotate`：生成新签名密钥并输出可直接粘贴的配置片段
//! - `user-hash`：生成 Argon2id 密码哈希并输出 env/CLI/YAML 三种配置片段
//! - `one-time-access-token`：为指定用户签发短时效一次性登录凭据
//!
//! # 用法
//!
//! ```sh
//! cargo build --bins --features cli-ops,account-credential,db-sqlite
//! ./target/debug/garrison-cli --help
//! ```
use clap::{Parser, Subcommand};
use garrison::error::{GarrisonError, GarrisonResult};

/// garrison-cli 命令行入口。
#[derive(Parser, Debug)]
#[command(name = "garrison-cli", version, about = "Garrison 运维工具")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// 对本机 auth_server 外网端口执行存活探测（/healthz）
    Healthcheck {
        /// 探测端口（缺省读 GARRISON_EXTERNAL_PORT，未设置回退 8080）
        #[arg(long)]
        port: Option<u16>,
    },
    /// 生成新签名密钥并输出可直接粘贴的配置片段
    KeyRotate {
        /// 额外独立生成一把会话密钥（当前版本 garrison 会话令牌与 JWT 共用
        /// jwt_secret 槽位；独立值供会话层单独密封的拆分部署使用）
        #[arg(long)]
        session_key: bool,
    },
    /// 生成 Argon2id 密码哈希并输出 env/CLI/YAML 三种配置片段
    UserHash {
        /// 用户名（不可为空、不可含 ':'——凭据串以 ':' 分隔用户与哈希）
        #[arg(long)]
        user: String,
        /// 明文密码（哈希后即丢弃；也可经 GARRISON_CLI_PASSWORD 传入避免进
        /// shell history）
        #[arg(long)]
        password: Option<String>,
        /// Argon2 并发令牌池大小（0 由 with_pool 钳制为 1）
        #[arg(long, default_value_t = 1)]
        pool_size: usize,
        /// env 片段中的 '$' 转义为 '$$'（docker-compose 变量插值场景；
        /// CLI/YAML 片段不受影响）
        #[arg(long)]
        escape_dollar: bool,
    },
    /// 为指定用户签发短时效一次性登录凭据
    OneTimeAccessToken {
        /// 数据库连接 URL（如 sqlite:///var/lib/garrison/garrison.db 或
        /// postgres://...；sqlite 文件必须已存在，驱动不为其自动建库；
        /// 凭据登记与用户查询都在该库）
        #[arg(long)]
        db_url: String,
        /// 目标用户名（不可为空）
        #[arg(long)]
        user: String,
        /// 租户 ID（0 = 默认租户）
        #[arg(long, default_value_t = 0)]
        tenant_id: i64,
        /// 凭据有效期秒数（必须 > 0）
        #[arg(long, default_value_t = 300)]
        ttl_seconds: u64,
        /// 签名密钥（缺省读 GARRISON_JWT_SECRET；两处都未设置则显性报错）
        #[arg(long)]
        secret: Option<String>,
        /// 迁移脚本基目录（幂等执行 core 迁移，保证空库可直接签发）
        #[arg(long, default_value = "migrations/sqlite")]
        migrations_dir: String,
    },
    /// 字段静态加密：全量重加密到新主钥（事务批处理，change-key）
    ChangeKey {
        /// 数据库连接 URL（sqlite 文件必须已存在）
        #[arg(long)]
        db_url: String,
        /// 租户标识（AAD 绑定成分，须与运行时配置一致）
        #[arg(long, default_value = "default")]
        tenant: String,
        /// 新密钥集，格式 `key_id:hex`（hex 恰 64 字符 = 32 字节），可重复传
        /// 递多把；第一把为主钥（新写入用它加密）
        #[arg(long = "key")]
        keys: Vec<String>,
        /// 批处理大小（每批扫描的敏感命名空间 key 数，必须 > 0）
        #[arg(long, default_value_t = 200)]
        batch_size: usize,
    },
    /// 字段静态加密：可解密性校验（check-key，不改动任何行）
    CheckKey {
        /// 数据库连接 URL（sqlite 文件必须已存在）
        #[arg(long)]
        db_url: String,
        /// 租户标识（AAD 绑定成分，须与运行时配置一致）
        #[arg(long, default_value = "default")]
        tenant: String,
        /// 密钥集，格式 `key_id:hex`（hex 恰 64 字符 = 32 字节），可重复传递
        #[arg(long = "key")]
        keys: Vec<String>,
        /// 敏感命名空间 glob（缺省全量扫描）
        #[arg(long, default_value = "*")]
        pattern: String,
    },
}

fn main() -> GarrisonResult<()> {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| GarrisonError::Internal(format!("cli-runtime-build::{}", e)))?;
    runtime.block_on(dispatch(cli.command))
}

async fn dispatch(command: Command) -> GarrisonResult<()> {
    match command {
        Command::Healthcheck { port } => run_healthcheck(port).await,
        Command::KeyRotate { session_key } => run_key_rotate(session_key).await,
        Command::UserHash {
            user,
            password,
            pool_size,
            escape_dollar,
        } => run_user_hash(user, password, pool_size, escape_dollar).await,
        Command::OneTimeAccessToken {
            db_url,
            user,
            tenant_id,
            ttl_seconds,
            secret,
            migrations_dir,
        } => {
            run_one_time_access_token(db_url, user, tenant_id, ttl_seconds, secret, migrations_dir)
                .await
        },
        Command::ChangeKey {
            db_url,
            tenant,
            keys,
            batch_size,
        } => run_change_key(db_url, tenant, keys, batch_size).await,
        Command::CheckKey {
            db_url,
            tenant,
            keys,
            pattern,
        } => run_check_key(db_url, tenant, keys, pattern).await,
    }
}

/// 解析 `key_id:hex` 参数表（hex 恰 64 字符 = 32 字节），供
/// [`garrison::secure::encryption::FieldCipher::from_key_entries`] 装配。
fn parse_key_entries(specs: &[String]) -> GarrisonResult<Vec<(String, String)>> {
    if specs.is_empty() {
        return Err(GarrisonError::InvalidParam(
            "cli-key-specs-empty::pass at least one --key key_id:hex".to_string(),
        ));
    }
    let mut keys = Vec::with_capacity(specs.len());
    for spec in specs {
        let (key_id, hex) = spec.split_once(':').ok_or_else(|| {
            GarrisonError::InvalidParam(format!(
                "cli-key-spec-format::expected key_id:hex got {spec}"
            ))
        })?;
        if key_id.is_empty() {
            return Err(GarrisonError::InvalidParam(format!(
                "cli-key-spec-empty-id::{spec}"
            )));
        }
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(GarrisonError::InvalidParam(format!(
                "cli-key-spec-hex-invalid::{key_id}::hex must be exactly 64 hex chars (32 bytes)"
            )));
        }
        keys.push((key_id.to_string(), hex.to_ascii_lowercase()));
    }
    Ok(keys)
}

async fn run_change_key(
    db_url: String,
    tenant: String,
    key_specs: Vec<String>,
    batch_size: usize,
) -> GarrisonResult<()> {
    // StaticFieldKeyProvider/from_key_entries 语义：首把即主钥（新写入用它
    // 加密）——--key 按「新钥集」传参，新主钥放第一位
    let cipher = garrison::secure::encryption::FieldCipher::from_key_entries(&parse_key_entries(
        &key_specs,
    )?)?;
    let pool = garrison::dao::init_dbnexus(&db_url).await?;
    let inner: std::sync::Arc<dyn garrison::dao::GarrisonDao> =
        std::sync::Arc::new(garrison::dao::GarrisonDaoDbnexus::new(
            pool,
            std::sync::Arc::new(garrison::dao::InMemoryDao::new()),
        ));
    let dao = garrison::secure::encryption::FieldEncryptionDao::new(
        inner.clone(),
        std::sync::Arc::new(cipher.clone()),
        &tenant,
    )?;
    let new_cipher = garrison::secure::encryption::FieldCipher::from_key_entries(
        &parse_key_entries(&key_specs)?,
    )?;
    let report = dao.change_key(new_cipher, batch_size).await?;
    println!(
        "change-key complete (tenant={tenant}, batch={batch_size}):\n  scanned: {}\n  reencrypted: {}\n  legacy_plaintext_reencrypted: {}\n  legacy_key_migrated: {}",
        report.scanned,
        report.reencrypted,
        report.legacy_plaintext_reencrypted,
        report.legacy_key_migrated
    );
    Ok(())
}

async fn run_check_key(
    db_url: String,
    tenant: String,
    key_specs: Vec<String>,
    pattern: String,
) -> GarrisonResult<()> {
    let cipher = garrison::secure::encryption::FieldCipher::from_key_entries(&parse_key_entries(
        &key_specs,
    )?)?;
    let pool = garrison::dao::init_dbnexus(&db_url).await?;
    let inner: std::sync::Arc<dyn garrison::dao::GarrisonDao> =
        std::sync::Arc::new(garrison::dao::GarrisonDaoDbnexus::new(
            pool,
            std::sync::Arc::new(garrison::dao::InMemoryDao::new()),
        ));
    let dao = garrison::secure::encryption::FieldEncryptionDao::new(
        inner,
        std::sync::Arc::new(cipher),
        &tenant,
    )?;
    let report = dao.check_key(&pattern).await?;
    println!(
        "check-key report (tenant={tenant}, pattern={pattern}):\n  scanned: {}\n  encrypted_ok: {}\n  legacy_plaintext: {}\n  legacy_raw_key: {}\n\n  non-zero legacy counts mean migration is incomplete; run change-key to converge.",
        report.scanned,
        report.encrypted_ok,
        report.legacy_plaintext,
        report.legacy_raw_key
    );
    Ok(())
}

/// 生成 256-bit 签名密钥：直接读 OS CSPRNG（`getrandom::fill`，无用户态 DRBG
/// 缓冲），与 csrf/授权码路径同一安全立场；hex 编码为 64 字符。
fn generate_signing_key() -> GarrisonResult<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| GarrisonError::Internal(format!("cli-keygen-csprng::{}", e)))?;
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    Ok(out)
}

/// key-rotate 报告：新签名密钥 + 可直接粘贴的安装片段。
///
/// 替换语义说明：garrison 的签名密钥来自配置（`jwt_secret`，无独立密钥库），
/// 轮换即「生成新钥 → 运维将片段安装进配置 → 重启」。重启后旧钥签发的
/// token 立即验证失败（无并存验签窗口，密钥无版本化存储）。
///
/// `with_session_key = true` 时额外独立生成一把会话密钥：当前版本 garrison
/// 的会话令牌（simple/jwt token_style）与 JWT 共用 `jwt_secret` 槽位
/// （`src/stp/token.rs`），标准部署安装签名密钥片段即可同时完成两层轮换；
/// 独立值供会话层单独密封的拆分部署使用。
fn key_rotate_report(with_session_key: bool) -> GarrisonResult<String> {
    // 生成的密钥经 JwtSecret 持有（protocol-zeroize 下为 Zeroizing<String>，
    // 离开作用域自动清零缓冲），报告文本是唯一交付面
    let signing = generate_signing_key()?;
    let signing_secret = garrison::config::JwtSecret::from(signing);
    let mut report = String::new();
    report.push_str(
        "Generated new signing key (256-bit, OS CSPRNG).\n\
         Install the fragment below and restart: tokens signed with the \
         previous key fail verification immediately after rotation.\n\n",
    );
    report.push_str("env:\n");
    // 安装片段顶格输出：可直接整行复制/机器提取
    report.push_str(&format!(
        "export GARRISON_JWT_SECRET={}\n\n",
        signing_secret.as_str()
    ));
    report.push_str("toml:\n");
    report.push_str(&format!("jwt_secret = \"{}\"\n", signing_secret.as_str()));
    if with_session_key {
        let session = generate_signing_key()?;
        let session_secret = garrison::config::JwtSecret::from(session);
        report.push_str("\nsession key (--session-key, generated independently):\n");
        report.push_str(&format!("{}\n", session_secret.as_str()));
        report.push_str(
            "\n  note: session tokens (simple/jwt token_style) are signed with\n  \
             jwt_secret in this version - stock deployments only need the\n  \
             signing fragment above; use this value when the session layer\n  \
             is sealed with a separate key in split deployments.\n",
        );
    }
    Ok(report)
}

async fn run_key_rotate(with_session_key: bool) -> GarrisonResult<()> {
    print!("{}", key_rotate_report(with_session_key)?);
    Ok(())
}

/// healthcheck 子命令：与 garrison-healthcheck 探针 bin 共用
/// `garrison::health::probe` 同一组判定函数，行为一致。
async fn run_healthcheck(port_override: Option<u16>) -> GarrisonResult<()> {
    let port = match port_override {
        Some(p) => p,
        None => garrison::health::probe::parse_port(
            std::env::var("GARRISON_EXTERNAL_PORT").ok().as_deref(),
        )
        .map_err(GarrisonError::InvalidParam)?,
    };
    // 探针为阻塞式 std socket I/O，移入 blocking 线程避免占用 runtime worker
    let result = tokio::task::spawn_blocking(move || garrison::health::probe::probe(port))
        .await
        .map_err(|e| GarrisonError::Internal(format!("cli-healthcheck-join::{}", e)))?;
    match result {
        Ok(code) if garrison::health::probe::is_healthy(code) => {
            println!("healthy: /healthz on 127.0.0.1:{port} returned {code}");
            Ok(())
        },
        Ok(code) => Err(GarrisonError::InvalidParam(format!(
            "cli-healthcheck-status::/healthz on 127.0.0.1:{port} returned non-2xx status {code}"
        ))),
        Err(reason) => Err(GarrisonError::InvalidParam(format!(
            "cli-healthcheck-failed::{reason}"
        ))),
    }
}

// 其余子命令按依赖任务逐个接线；未接线前显性报错而非静默退出。
async fn run_user_hash(
    user: String,
    password: Option<String>,
    pool_size: usize,
    escape_dollar: bool,
) -> GarrisonResult<()> {
    let password = match password {
        Some(p) => p,
        None => std::env::var("GARRISON_CLI_PASSWORD").map_err(|_| {
            GarrisonError::InvalidParam(
                "cli-user-hash-password-missing::pass --password or set GARRISON_CLI_PASSWORD"
                    .to_string(),
            )
        })?,
    };
    print!(
        "{}",
        user_hash_report(&user, &password, pool_size, escape_dollar)?
    );
    Ok(())
}

/// 校验用户名：非空且不含 ':'（凭据串以 ':' 分隔用户与哈希，含 ':' 会
/// 使消费方解析歧义）。
fn validate_username(user: &str) -> GarrisonResult<()> {
    if user.is_empty() {
        return Err(GarrisonError::InvalidParam(
            "cli-user-hash-user-empty::".to_string(),
        ));
    }
    if user.contains(':') {
        return Err(GarrisonError::InvalidParam(
            "cli-user-hash-user-colon::username must not contain ':'".to_string(),
        ));
    }
    Ok(())
}

/// user-hash 报告：`username:hash` 凭据串的 env/CLI/YAML 三种安装片段。
///
/// 凭据串格式与 tinyauth 的 `user:hash` 约定对齐；garrison 侧无内建用户列表
/// 配置槽，片段交由部署方的 bootstrap 装配消费（种子写入 app_user 表的
/// username/password_hash 列）。
fn user_hash_report(
    user: &str,
    password: &str,
    pool_size: usize,
    escape_dollar: bool,
) -> GarrisonResult<String> {
    validate_username(user)?;
    if password.is_empty() {
        return Err(GarrisonError::InvalidParam(
            "cli-user-hash-password-empty::".to_string(),
        ));
    }
    use garrison::account::credential::password::{Argon2Hasher, PasswordHasher as _};
    let hasher = Argon2Hasher::default().with_pool(pool_size);
    let hash = hasher.hash(password)?;
    let credential = format!("{user}:{hash}");
    let env_value = if escape_dollar {
        credential.replace('$', "$$")
    } else {
        credential.clone()
    };
    Ok(format!(
        "Created Argon2id hash for user '{user}' (pool={pool_size}; pool_size=0 is clamped to 1).\n\n\
         env:\nexport GARRISON_BOOTSTRAP_USERS={env_value}\n\n\
         cli:\n--bootstrap-users {credential}\n\n\
         yaml:\nbootstrap_users: \"{credential}\"\n\n\
         note: for docker-compose env interpolation use --escape-dollar;\n\
         wire the credential into your bootstrap seeding (app_user.username /\n\
         app_user.password_hash) and restart.\n"
    ))
}

/// 签发一次性登录凭据的持久化登记键（app_user_ext.field_key，每用户固定单行：
/// 值为 `<jti>|<exp RFC3339>`，行存在 = 该用户尚有未消费的一次性凭据）。
const ONE_TIME_LOGIN_REGISTRY_KEY: &str = "one_time_login";

/// 一次性登录凭据签发结果。
///
/// `Debug` 手工实现：token 本体脱敏（错误路径日志不得携带可用凭据）。
struct IssuedOneTimeToken {
    /// 自包含 JWT（sub/login_id = user_id，exp = iat + ttl，jti 唯一）。
    token: String,
    /// JWT 唯一标识（与登记键一一对应）。
    jti: String,
    user_id: String,
    username: String,
    tenant_id: i64,
    /// 过期时间（Unix 秒）。
    expires_at_unix: i64,
    /// 一次性消费登记行的 field_key（[`ONE_TIME_LOGIN_REGISTRY_KEY`]）。
    registry_field_key: String,
}

impl std::fmt::Debug for IssuedOneTimeToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedOneTimeToken")
            .field("token", &"<redacted>")
            .field("jti", &self.jti)
            .field("user_id", &self.user_id)
            .field("username", &self.username)
            .field("tenant_id", &self.tenant_id)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("registry_field_key", &self.registry_field_key)
            .finish()
    }
}

/// 签发一次性登录凭据：按用户名查询 → 状态校验 → JWT 签发 → 一次性消费
/// 登记（app_user_ext 行，存在 = 未消费，业务方消费后删除该行）。
///
/// 同一用户重复签发覆盖旧登记行（UK(user_id, field_key) upsert 语义）：
/// 旧 token 的登记随新签发失效（last-issuance-wins），但旧 token 本体在
/// exp 前仍可通过验签——需要立即吊销时用同一密钥换发或等待过期。
async fn issue_one_time_access_token(
    users: &dyn garrison::dao::repository::UserRepository,
    ext: &dyn garrison::dao::repository::UserExtRepository,
    tenant_id: i64,
    username: &str,
    ttl_seconds: u64,
    signing_secret: &str,
) -> GarrisonResult<IssuedOneTimeToken> {
    if ttl_seconds == 0 {
        return Err(GarrisonError::InvalidParam(
            "cli-one-time-ttl-invalid::ttl must be > 0".to_string(),
        ));
    }
    if signing_secret.is_empty() {
        return Err(GarrisonError::InvalidParam(
            "cli-one-time-secret-empty::signing secret must not be empty".to_string(),
        ));
    }
    let user = users
        .find_by_username(tenant_id, username)
        .await?
        .ok_or_else(|| {
            GarrisonError::InvalidParam(format!(
                "cli-one-time-user-not-found::no user {username:?} in tenant {tenant_id}"
            ))
        })?;
    if user.status != "active" {
        return Err(GarrisonError::InvalidParam(format!(
            "cli-one-time-user-not-active::user {username:?} status is {:?} (only active users may be issued one-time credentials)",
            user.status
        )));
    }

    // 过期时间从签发设施解码取回（不本地重算），保证登记值与凭据一致
    let handler = garrison::protocol::jwt::JwtHandler::new(signing_secret);
    let token = handler.sign(&user.id, ttl_seconds as i64)?;
    let claims = handler.verify(&token)?;
    let jti = claims.jti.clone().ok_or_else(|| {
        GarrisonError::Internal("cli-one-time-jti-missing::signed token lacks jti".to_string())
    })?;
    // 登记值 = `<jti>|<exp RFC3339>`：消费方比对 jti 防串用，过期行可由 GC 清扫；
    // 每用户固定单行，重复签发经 upsert 自然覆盖（last-issuance-wins）
    let expires_at_rfc3339 = chrono::DateTime::from_timestamp(claims.exp, 0).ok_or_else(|| {
        GarrisonError::Internal(format!("cli-one-time-exp-out-of-range::{}", claims.exp))
    })?;
    let registry_value = format!("{jti}|{}", expires_at_rfc3339.to_rfc3339());
    ext.upsert(
        tenant_id,
        &user.id,
        ONE_TIME_LOGIN_REGISTRY_KEY,
        Some(registry_value),
        "string",
    )
    .await?;
    Ok(IssuedOneTimeToken {
        token,
        jti,
        user_id: user.id,
        username: user.username,
        tenant_id,
        expires_at_unix: claims.exp,
        registry_field_key: ONE_TIME_LOGIN_REGISTRY_KEY.to_string(),
    })
}

async fn run_one_time_access_token(
    db_url: String,
    user: String,
    tenant_id: i64,
    ttl_seconds: u64,
    secret: Option<String>,
    migrations_dir: String,
) -> GarrisonResult<()> {
    let signing_secret = match secret {
        Some(s) => s,
        None => std::env::var("GARRISON_JWT_SECRET").map_err(|_| {
            GarrisonError::InvalidParam(
                "cli-one-time-secret-missing::pass --secret or set GARRISON_JWT_SECRET".to_string(),
            )
        })?,
    };
    let pool = garrison::dao::init_dbnexus(&db_url).await?;
    let migration =
        garrison::dao::GarrisonMigration::with_base_dir(pool.clone(), migrations_dir.into());
    migration
        .migrate_core()
        .await
        .map_err(|e| GarrisonError::Config(format!("cli-one-time-migrate::{e}")))?;
    let users = garrison::dao::repository::sqlite::DbnexusUserRepository::new(pool.clone());
    let ext = garrison::dao::repository::sqlite::DbnexusUserExtRepository::new(pool);
    let issued =
        issue_one_time_access_token(&users, &ext, tenant_id, &user, ttl_seconds, &signing_secret)
            .await?;
    let expires_at_rfc3339 = chrono::DateTime::from_timestamp(issued.expires_at_unix, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| issued.expires_at_unix.to_string());
    print!(
        "Issued one-time access token for user '{}' (tenant {}).\n\n\
         token:\n{}\n\n\
         expires at: {} (unix {})\n\
         one-time registry: app_user_ext field_key = {}\n\n\
         consumption: server verifies the token with the same signing secret,\n\
         then deletes the registry row (find_by_user_and_key + delete) before\n\
         creating the session - a second use finds no row and must be rejected.\n\
         Re-issuing for the same user replaces the registry row.\n",
        issued.username,
        issued.tenant_id,
        issued.token,
        expires_at_rfc3339,
        issued.expires_at_unix,
        issued.registry_field_key
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn subcommand_surface_is_the_four_ops_commands() {
        let cmd = Cli::command();
        let names: Vec<&str> = cmd
            .get_subcommands()
            .map(|s| s.get_name())
            .filter(|n| *n != "help")
            .collect();
        assert_eq!(
            names,
            vec![
                "healthcheck",
                "key-rotate",
                "user-hash",
                "one-time-access-token",
                "change-key",
                "check-key"
            ],
            "子命令面必须与运维需求一一对应（help 为 clap 自动附加，不计入）"
        );
    }

    #[test]
    fn subcommand_names_are_kebab_case() {
        let cmd = Cli::command();
        for sub in cmd.get_subcommands().filter(|s| s.get_name() != "help") {
            assert!(
                sub.get_name()
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '-'),
                "子命令名 {} 应为 kebab-case",
                sub.get_name()
            );
        }
    }

    /// 起本地一次性 HTTP 假服务端，返回其临时端口。
    fn serve_once(response: &'static str) -> u16 {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 1024];
            let _ = conn.read(&mut buf);
            conn.write_all(response.as_bytes()).expect("write response");
        });
        port
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn healthcheck_ok_on_live_target() {
        let port = serve_once("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        run_healthcheck(Some(port))
            .await
            .expect("live target must be reported healthy");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn healthcheck_fails_on_non_2xx() {
        let port = serve_once("HTTP/1.1 503 Service Unavailable\r\n\r\n");
        let err = run_healthcheck(Some(port))
            .await
            .expect_err("503 must not be reported healthy");
        let reason = err.to_string();
        assert!(
            reason.contains("503"),
            "错误原因必须携带状态码，实际: {reason}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn healthcheck_fails_on_dead_port() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);
        let err = run_healthcheck(Some(port))
            .await
            .expect_err("dead port must fail");
        let reason = err.to_string();
        assert!(
            reason.contains("connect 127.0.0.1"),
            "连接失败必须显性报错，实际: {reason}"
        );
    }

    // ========================================================================
    // key-rotate 子命令
    // ========================================================================

    #[test]
    fn generated_signing_key_is_256bit_hex_and_unique() {
        let first = generate_signing_key().expect("keygen must succeed");
        let second = generate_signing_key().expect("keygen must succeed");
        assert_eq!(first.len(), 64, "256-bit 密钥应编码为 64 个 hex 字符");
        assert!(
            first.chars().all(|c| c.is_ascii_hexdigit()),
            "密钥必须为 hex 编码，实际: {first}"
        );
        assert_ne!(first, second, "两次生成必须得到独立密钥");
    }

    #[test]
    fn key_rotate_report_contains_all_install_fragments() {
        let report = key_rotate_report(true).expect("report must build");
        assert!(
            report.contains("GARRISON_JWT_SECRET="),
            "env 安装片段缺失:\n{report}"
        );
        assert!(
            report.contains("jwt_secret = \""),
            "TOML 安装片段缺失:\n{report}"
        );
        // 会话密钥无独立配置槽位（与 jwt_secret 共用），故只交付裸值，
        // 不伪造 GARRISON_SESSION_KEY= 之类的环境变量映射
        let signing = report
            .lines()
            .find(|l| l.starts_with("export GARRISON_JWT_SECRET="))
            .map(|l| {
                l.trim_start_matches("export GARRISON_JWT_SECRET=")
                    .to_string()
            })
            .expect("env 片段行必须携带签名密钥值");
        let session = report
            .lines()
            .find(|l| l.len() == 64 && l.chars().all(|c| c.is_ascii_hexdigit()) && *l != signing)
            .expect("--session-key 必须额外产出独立会话密钥裸值");
        assert_ne!(signing, session, "签名密钥与会话密钥必须独立生成");
    }

    /// 轮换语义验收：新钥安装后，旧钥签发的 token 必须验证失败，新钥签发的
    /// token 必须验证成功（JwtHandler 为既有签名设施，此处不改其行为）。
    #[test]
    fn key_rotation_rejects_old_key_tokens_and_accepts_new() {
        use garrison::protocol::jwt::JwtHandler;

        let old_key = generate_signing_key().expect("old keygen");
        let new_key = key_rotate_report(false)
            .expect("rotation report")
            .lines()
            .find(|l| l.starts_with("export GARRISON_JWT_SECRET="))
            .map(|l| {
                l.trim_start_matches("export GARRISON_JWT_SECRET=")
                    .to_string()
            })
            .expect("轮换报告必须携带新签名密钥");

        let old_handler = JwtHandler::new(&old_key);
        let new_handler = JwtHandler::new(&new_key);

        let old_token = old_handler.sign("user-1", 3600).expect("旧钥签发必须成功");

        let old_under_new = new_handler.verify(&old_token);
        assert!(
            old_under_new.is_err(),
            "轮换后旧钥 token 必须验证失败，不得静默通过"
        );

        let new_token = new_handler.sign("user-1", 3600).expect("新钥签发必须成功");
        let claims = new_handler
            .verify(&new_token)
            .expect("新钥 token 必须验证成功");
        assert_eq!(claims.login_id, "user-1");
    }

    // ========================================================================
    // user-hash 子命令
    // ========================================================================

    const HASH_TEST_USER: &str = "ops-admin";
    const HASH_TEST_PASSWORD: &str = "correct horse battery staple";

    /// 从报告 YAML 片段提取凭据串（`user:hash`）。
    fn extract_yaml_credential(report: &str) -> String {
        let line = report
            .lines()
            .find(|l| l.starts_with("bootstrap_users: \""))
            .expect("YAML 片段行必须存在");
        line.trim_start_matches("bootstrap_users: \"")
            .trim_end_matches('"')
            .to_string()
    }

    #[test]
    fn user_hash_report_emits_hash_that_verifies() {
        let report = user_hash_report(HASH_TEST_USER, HASH_TEST_PASSWORD, 1, false)
            .expect("report must build");
        let credential = extract_yaml_credential(&report);
        let hash = credential
            .strip_prefix(&format!("{HASH_TEST_USER}:"))
            .expect("凭据串必须以 user: 开头");
        assert!(
            hash.starts_with("$argon2id$"),
            "必须是 Argon2id PHC 格式，实际: {hash}"
        );
        use garrison::account::credential::password::{Argon2Hasher, PasswordHasher as _};
        let verifier = Argon2Hasher::default();
        assert!(
            verifier
                .verify(HASH_TEST_PASSWORD, hash)
                .expect("verify must not error"),
            "报告中的哈希必须能验证原密码"
        );
        assert!(
            !verifier
                .verify("wrong-password", hash)
                .expect("verify must not error"),
            "错误密码必须验证失败"
        );
    }

    /// confers 派生配置 fixture：模拟部署方 bootstrap 装配的消费面
    /// （env 前缀与片段约定一致）。Option 字段缺省 None（confers 派生
    /// 不接受空串字面量默认值）。
    #[derive(Debug, serde::Deserialize, confers::Config)]
    #[config(env_prefix = "GARRISON_")]
    struct BootstrapUsersFixture {
        bootstrap_users: Option<String>,
    }

    /// env 片段可被 confers 配置加载：片段值注入 GARRISON_BOOTSTRAP_USERS
    /// 后经派生 Config 加载还原。
    #[test]
    #[serial_test::serial]
    fn env_fragment_is_loadable_by_confers() {
        let report = user_hash_report(HASH_TEST_USER, HASH_TEST_PASSWORD, 1, false)
            .expect("report must build");
        let credential = report
            .lines()
            .find(|l| l.starts_with("export GARRISON_BOOTSTRAP_USERS="))
            .map(|l| {
                l.trim_start_matches("export GARRISON_BOOTSTRAP_USERS=")
                    .to_string()
            })
            .expect("env 片段行必须存在");

        // 串行化执行：set_var/remove_var 与其它 env 测试互斥
        std::env::set_var("GARRISON_BOOTSTRAP_USERS", &credential);
        let loaded = BootstrapUsersFixture::load_sync().expect("confers 加载必须成功");
        std::env::remove_var("GARRISON_BOOTSTRAP_USERS");
        assert_eq!(
            loaded.bootstrap_users.as_deref(),
            Some(credential.as_str()),
            "env 片段必须无损还原"
        );
    }

    /// YAML 片段可被 confers 配置加载：片段写入 .yaml 文件后经
    /// FileSource（yaml 转换器）构建还原。
    #[test]
    fn yaml_fragment_is_loadable_by_confers() {
        let report = user_hash_report(HASH_TEST_USER, HASH_TEST_PASSWORD, 1, false)
            .expect("report must build");
        let credential = extract_yaml_credential(&report);
        let yaml = format!("bootstrap_users: \"{credential}\"\n");

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bootstrap.yaml");
        std::fs::write(&path, yaml).expect("write yaml fragment");
        let config = confers::config::ConfigBuilder::<BootstrapUsersFixture>::new()
            .source(Box::new(
                confers::config::FileSource::new(path.to_str().expect("utf8 path"))
                    .with_priority(10)
                    .with_loader_config(
                        confers::loader::LoaderConfig::new()
                            .allow_absolute()
                            .max_size(64 * 1024)
                            .redact_error_paths(),
                    ),
            ))
            .build()
            .expect("yaml 片段必须可被 confers 加载");
        assert_eq!(
            config.bootstrap_users.as_deref(),
            Some(credential.as_str()),
            "YAML 片段必须无损还原"
        );
    }

    /// CLI 片段载荷与 env/YAML 同源：`--bootstrap-users <cred>` 的值即
    /// 凭据串，注入同一 env 约定后可被 confers 加载。
    #[test]
    #[serial_test::serial]
    fn cli_fragment_payload_is_loadable_by_confers() {
        let report = user_hash_report(HASH_TEST_USER, HASH_TEST_PASSWORD, 1, false)
            .expect("report must build");
        let credential = report
            .lines()
            .find(|l| l.starts_with("--bootstrap-users "))
            .map(|l| l.trim_start_matches("--bootstrap-users ").to_string())
            .expect("CLI 片段行必须存在");

        std::env::set_var("GARRISON_BOOTSTRAP_USERS", &credential);
        let loaded = BootstrapUsersFixture::load_sync().expect("confers 加载必须成功");
        std::env::remove_var("GARRISON_BOOTSTRAP_USERS");
        assert_eq!(
            loaded.bootstrap_users.as_deref(),
            Some(credential.as_str()),
            "CLI 片段必须无损还原"
        );
    }

    #[test]
    fn user_hash_rejects_invalid_input_explicitly() {
        let empty_user =
            user_hash_report("", HASH_TEST_PASSWORD, 1, false).expect_err("空用户名必须显性报错");
        assert!(empty_user.to_string().contains("user-empty"));
        let colon_user = user_hash_report("a:b", HASH_TEST_PASSWORD, 1, false)
            .expect_err("含 ':' 用户名必须显性报错");
        assert!(colon_user.to_string().contains("user-colon"));
        let empty_password =
            user_hash_report(HASH_TEST_USER, "", 1, false).expect_err("空密码必须显性报错");
        assert!(empty_password.to_string().contains("password-empty"));
    }

    #[test]
    fn escape_dollar_only_affects_env_fragment() {
        // Argon2 每次随机盐，跨报告的哈希值不同——断言必须在同一份报告内闭环
        let plain =
            user_hash_report(HASH_TEST_USER, HASH_TEST_PASSWORD, 1, false).expect("plain report");
        let plain_cred = extract_yaml_credential(&plain);
        let plain_env_value = plain
            .lines()
            .find(|l| l.starts_with("export GARRISON_BOOTSTRAP_USERS="))
            .map(|l| {
                l.trim_start_matches("export GARRISON_BOOTSTRAP_USERS=")
                    .to_string()
            })
            .expect("env 行");
        assert!(plain_cred.contains('$'), "PHC 哈希必然含 $");
        assert_eq!(plain_env_value, plain_cred, "默认 env 片段不转义");

        let escaped =
            user_hash_report(HASH_TEST_USER, HASH_TEST_PASSWORD, 1, true).expect("escaped report");
        let escaped_cred = extract_yaml_credential(&escaped);
        let escaped_env_value = escaped
            .lines()
            .find(|l| l.starts_with("export GARRISON_BOOTSTRAP_USERS="))
            .map(|l| {
                l.trim_start_matches("export GARRISON_BOOTSTRAP_USERS=")
                    .to_string()
            })
            .expect("escaped env 行");
        assert_eq!(
            escaped_env_value,
            escaped_cred.replace('$', "$$"),
            "escape_dollar 开启时仅 env 片段将 $ 转义为 $$"
        );
        // CLI/YAML 片段保持原值（YAML 与命令行参数无变量插值）
        assert!(!escaped_cred.contains("$$"), "YAML 片段不应转义");
        assert!(
            escaped.contains(&format!("--bootstrap-users {escaped_cred}")),
            "CLI 片段不应转义"
        );
    }

    // ========================================================================
    // one-time-access-token 子命令
    // ========================================================================

    use garrison::dao::repository::sqlite::{DbnexusUserExtRepository, DbnexusUserRepository};
    use garrison::dao::repository::{NewUser, UserExtRepository, UserRepository};
    use garrison::dao::{init_dbnexus, GarrisonMigration};

    const ONE_TIME_SECRET: &str = "one-time-access-token-test-secret-0123456789abcdef";

    /// sqlite 内存库：执行 core 迁移 + 可选预置用户，返回 (用户仓库, 扩展字段仓库)。
    async fn one_time_fixture(
        seed_users: &[(&str, &str)], // (username, status)
    ) -> (DbnexusUserRepository, DbnexusUserExtRepository) {
        let pool = init_dbnexus("sqlite::memory:")
            .await
            .expect("init_dbnexus must succeed");
        let migrations_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("migrations")
            .join("sqlite");
        GarrisonMigration::with_base_dir(pool.clone(), migrations_dir)
            .migrate_core()
            .await
            .expect("migrate_core must succeed");
        let users = DbnexusUserRepository::new(pool.clone());
        for (i, (username, status)) in seed_users.iter().enumerate() {
            users
                .create(
                    0,
                    NewUser {
                        username: username.to_string(),
                        // 合法 Argon2id PHC 形态（R11 导入校验门：前缀白名单 +
                        // 参数上限内；低位参数仅为测试占位，登录验证不在此路径）
                        password_hash: "$argon2id$m=8,t=1,p=1$seed".to_string(),
                        status: status.to_string(),
                    },
                )
                .await
                .unwrap_or_else(|e| panic!("seed user {i} must insert: {e}"));
        }
        (users, DbnexusUserExtRepository::new(pool))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_time_token_exp_matches_ttl() {
        let (users, ext) = one_time_fixture(&[("alice", "active")]).await;
        let ttl = 300u64;
        let issued = issue_one_time_access_token(&users, &ext, 0, "alice", ttl, ONE_TIME_SECRET)
            .await
            .expect("issuance must succeed");

        // exp 属性从签发设施验证：exp = iat + ttl，且窗口正确
        let handler = garrison::protocol::jwt::JwtHandler::new(ONE_TIME_SECRET);
        let claims = handler
            .verify(&issued.token)
            .expect("issued token must verify");
        assert_eq!(
            claims.exp,
            claims.iat + ttl as i64,
            "exp 必须等于 iat + ttl"
        );
        assert_eq!(claims.sub, issued.user_id, "sub 必须绑定目标用户");
        assert_eq!(issued.jti, claims.jti.expect("jti 必须存在"));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64;
        assert!(
            issued.expires_at_unix > now,
            "有效期必须落在未来（时钟未回拨的前提下）"
        );
        assert!(
            issued.expires_at_unix - now <= ttl as i64,
            "有效期不得超过 ttl"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_time_token_unknown_user_is_explicit_error() {
        let (users, ext) = one_time_fixture(&[]).await;
        let err = issue_one_time_access_token(&users, &ext, 0, "ghost", 300, ONE_TIME_SECRET)
            .await
            .expect_err("unknown user must fail explicitly");
        let reason = err.to_string();
        assert!(
            reason.contains("user-not-found") && reason.contains("ghost"),
            "未知用户必须显性报错且点名目标，实际: {reason}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_time_token_inactive_user_is_explicit_error() {
        let (users, ext) = one_time_fixture(&[("bob", "suspended")]).await;
        let err = issue_one_time_access_token(&users, &ext, 0, "bob", 300, ONE_TIME_SECRET)
            .await
            .expect_err("suspended user must fail explicitly");
        let reason = err.to_string();
        assert!(
            reason.contains("user-not-active"),
            "非 active 用户必须显性报错，实际: {reason}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_time_token_persists_one_time_registry_row() {
        let (users, ext) = one_time_fixture(&[("carol", "active")]).await;
        let issued = issue_one_time_access_token(&users, &ext, 0, "carol", 300, ONE_TIME_SECRET)
            .await
            .expect("issuance must succeed");

        let row = ext
            .find_by_user_and_key(0, &issued.user_id, &issued.registry_field_key)
            .await
            .expect("registry lookup must succeed")
            .expect("登记行必须存在（存在 = 未消费）");
        // 登记值 = `<jti>|<exp RFC3339>`，与凭据内容一致
        let stored = row.field_value.expect("登记值必须存在");
        let expected_exp = chrono::DateTime::from_timestamp(issued.expires_at_unix, 0)
            .expect("valid exp")
            .to_rfc3339();
        assert_eq!(
            stored,
            format!("{}|{}", issued.jti, expected_exp),
            "登记值必须为 jti|exp 形式且与凭据一致，实际: {stored}"
        );

        // last-issuance-wins：每用户固定单行，重复签发覆盖登记值（新 jti 替换旧 jti）
        let second = issue_one_time_access_token(&users, &ext, 0, "carol", 300, ONE_TIME_SECRET)
            .await
            .expect("second issuance must succeed");
        let replaced = ext
            .find_by_user_and_key(0, &second.user_id, &second.registry_field_key)
            .await
            .expect("registry lookup must succeed")
            .expect("登记行必须仍存在");
        let stored = replaced.field_value.expect("登记值必须存在");
        assert!(
            stored.starts_with(&second.jti),
            "重复签发后登记行必须指向新 jti，实际: {stored}"
        );
        assert!(
            !stored.contains(&issued.jti),
            "旧 jti 登记必须被覆盖，不得残留: {stored}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_time_token_rejects_zero_ttl_and_empty_secret() {
        let (users, ext) = one_time_fixture(&[("dave", "active")]).await;
        let zero_ttl = issue_one_time_access_token(&users, &ext, 0, "dave", 0, ONE_TIME_SECRET)
            .await
            .expect_err("ttl=0 must fail explicitly");
        assert!(zero_ttl.to_string().contains("ttl-invalid"));
        let empty_secret = issue_one_time_access_token(&users, &ext, 0, "dave", 300, "")
            .await
            .expect_err("空密钥必须显性报错");
        assert!(empty_secret.to_string().contains("secret-empty"));
    }
}
