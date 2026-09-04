# Deployment Notes

## `panic = "abort"` 与任务隔离语义

`Cargo.toml` 的 `[profile.release]` 设置了 `panic = "abort"`。其副作用：

- 进程遇到任何 `panic` 会**直接终止**，而非展开栈。
- `src/channel.rs` 与 `src/stp/context.rs` 中依赖 `std::panic::catch_unwind`
  实现的“隔离单个任务 panic、避免污染全局状态”语义，在 release 构建下会
  **退化为整个进程终止**。

### 生产环境建议

- 若业务依赖上述 catch_unwind 隔离语义（例如单进程内承载多租户任务），
  请改用 `panic = "unwind"`，或将任务边界放到独立线程 / 独立 tokio runtime /
  独立进程中，使单点 panic 只影响该边界。
- 配合进程级 supervisor（systemd `Restart=on-failure` / k8s
  `restartPolicy: Always`）保证 abort 后自动拉起。
- 仅在不可恢复场景下才主动 `panic`；可恢复错误应走 `Result`/`GarrisonResult`。

## 依赖锁定

本仓库提交 `Cargo.lock`，CI 使用 `--locked` 构建以保证依赖树可重现。
修改依赖后请重新 `cargo generate-lockfile` 并提交更新后的 `Cargo.lock`。
