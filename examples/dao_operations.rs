//! DAO 操作示例：演示 BulwarkDaoOxcache CRUD 与 BulwarkMigration 数据库迁移。
//!
//! 流程：
//! 1. 创建 oxcache DAO 实例（内存缓存后端）
//! 2. set + get 配对写入与读取
//! 3. TTL 过期自动删除
//! 4. update 更新值（保留 TTL）
//! 5. expire 重置过期时间
//! 6. delete 显式删除
//! 7. zero TTL 永久驻留
//! 8. BulwarkMigration 数据库迁移（feature = "db-sqlite"）
//!
//! 运行方式：
//! ```sh
//! cargo run --example dao_operations --features "cache-memory,db-sqlite"
//! ```

use bulwark::dao::{BulwarkDao, BulwarkDaoOxcache};
use bulwark::error::BulwarkResult;
use std::time::Duration;

#[cfg(feature = "db-sqlite")]
use bulwark::dao::{init_dbnexus, BulwarkMigration};

#[tokio::main]
async fn main() -> BulwarkResult<()> {
    println!("=== Bulwark DAO 操作示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 创建 oxcache DAO
    // ----------------------------------------------------------------
    let dao = BulwarkDaoOxcache::new().await?;
    println!("[1] BulwarkDaoOxcache 创建完成（sync_mode 启用）\n");

    // ----------------------------------------------------------------
    // 2. set + get 配对
    // ----------------------------------------------------------------
    dao.set("user:1:token", "abc123", 3600).await?;
    let value = dao.get("user:1:token").await?;
    println!("[2] set + get 配对:");
    println!("    set(\"user:1:token\", \"abc123\", 3600)");
    println!("    get → {:?}", value);
    println!();

    // ----------------------------------------------------------------
    // 3. TTL 过期（1 秒 TTL + 等待 2 秒）
    // ----------------------------------------------------------------
    dao.set("temp_key", "temp_value", 1).await?;
    println!("[3] TTL 过期:");
    println!("    set(\"temp_key\", \"temp_value\", ttl=1)");
    let before = dao.get("temp_key").await?;
    println!("    立即 get → {:?}", before);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let after = dao.get("temp_key").await?;
    println!("    2 秒后 get → {:?}（已过期）", after);
    println!();

    // ----------------------------------------------------------------
    // 4. update 更新值（保留 TTL）
    // ----------------------------------------------------------------
    dao.set("update_key", "old_value", 3600).await?;
    dao.update("update_key", "new_value").await?;
    let updated = dao.get("update_key").await?;
    println!("[4] update 保留 TTL:");
    println!("    set(\"update_key\", \"old_value\", 3600)");
    println!("    update(\"update_key\", \"new_value\")");
    println!("    get → {:?}（值已更新，TTL 保留）", updated);
    println!();

    // ----------------------------------------------------------------
    // 5. expire 重置过期时间
    // ----------------------------------------------------------------
    dao.set("expire_key", "value", 1).await?;
    dao.expire("expire_key", 3600).await?;
    println!("[5] expire 重置:");
    println!("    set(\"expire_key\", \"value\", ttl=1)");
    println!("    expire(\"expire_key\", 3600)（重置为 3600 秒）");
    tokio::time::sleep(Duration::from_secs(2)).await;
    let survived = dao.get("expire_key").await?;
    println!("    2 秒后 get → {:?}（原 TTL 已过，但 expire 重置后仍存在）", survived);
    println!();

    // ----------------------------------------------------------------
    // 6. delete 显式删除
    // ----------------------------------------------------------------
    dao.set("delete_key", "to_delete", 3600).await?;
    dao.delete("delete_key").await?;
    let deleted = dao.get("delete_key").await?;
    println!("[6] delete 删除:");
    println!("    set(\"delete_key\", \"to_delete\", 3600)");
    println!("    delete(\"delete_key\")");
    println!("    get → {:?}（已删除）", deleted);
    println!();

    // ----------------------------------------------------------------
    // 7. zero TTL 永久驻留
    // ----------------------------------------------------------------
    dao.set("permanent_key", "forever", 0).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let permanent = dao.get("permanent_key").await?;
    println!("[7] zero TTL 永久驻留:");
    println!("    set(\"permanent_key\", \"forever\", ttl=0)");
    println!("    2 秒后 get → {:?}（永久驻留，不过期）", permanent);
    println!();

    // ----------------------------------------------------------------
    // 8. BulwarkMigration 数据库迁移（feature = "db-sqlite"）
    // ----------------------------------------------------------------
    #[cfg(feature = "db-sqlite")]
    {
        println!("[8] BulwarkMigration 数据库迁移:");
        let db_url = "sqlite::memory:";
        let pool = init_dbnexus(db_url).await?;
        let migration = BulwarkMigration::new(pool);
        let count = migration.run_all().await?;
        println!("    run_all() 完成，执行了 {} 条迁移", count);
        println!();
    }

    #[cfg(not(feature = "db-sqlite"))]
    {
        println!("[8] BulwarkMigration 示例跳过（需启用 db-sqlite feature）\n");
    }

    println!("=== 示例执行完成 ===");
    Ok(())
}
