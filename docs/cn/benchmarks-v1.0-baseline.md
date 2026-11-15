# Garrison 性能基线

- 采集时间（UTC）：2026-10-19T18:37:06Z
- 基线名称：`v1.0-pre`
- git：`9efd85dd1fcc3f55186102c4e5c68a89e80bc3e1`
- rustc：`rustc 1.97.1 (8bab26f4f 2026-07-14)`
- cargo：`cargo 1.97.1 (c980f4866 2026-06-30)`
- 采样模式：full
- 说明：本文只记录同机相对基线；不同机器/负载下绝对值不可横向比较。

## 环境

```text
Linux Kirky 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun  5 18:30:46 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
model name    : AMD Ryzen 9 9950X 16-Core Processor
```

## 运行命令

```bash
cargo bench --features full --bench garrison_benchmark -- --save-baseline v1.0-pre
```

## criterion 输出

```text
Gnuplot not found, using plotters backend
Benchmarking login_flow
Benchmarking login_flow: Warming up for 3.0000 s
Benchmarking login_flow: Collecting 100 samples in estimated 5.6043 s (10k iterations)
Benchmarking login_flow: Analyzing
login_flow              time:   [2.0106 ms 2.1222 ms 2.2174 ms]

Benchmarking token_verify_stateless_jwt
Benchmarking token_verify_stateless_jwt: Warming up for 3.0000 s
Benchmarking token_verify_stateless_jwt: Collecting 100 samples in estimated 5.0049 s (4.9M iterations)
Benchmarking token_verify_stateless_jwt: Analyzing
token_verify_stateless_jwt
                        time:   [1.0093 µs 1.0159 µs 1.0226 µs]
Found 10 outliers among 100 measurements (10.00%)
  1 (1.00%) low mild
  5 (5.00%) high mild
  4 (4.00%) high severe

Benchmarking permission_check
Benchmarking permission_check: Warming up for 3.0000 s
Benchmarking permission_check: Collecting 100 samples in estimated 5.0011 s (3.3M iterations)
Benchmarking permission_check: Analyzing
permission_check        time:   [1.5289 µs 1.5343 µs 1.5405 µs]
Found 4 outliers among 100 measurements (4.00%)
  2 (2.00%) high mild
  2 (2.00%) high severe

Benchmarking oxcache_backend_switch/backend/memory
Benchmarking oxcache_backend_switch/backend/memory: Warming up for 3.0000 s
Benchmarking oxcache_backend_switch/backend/memory: Collecting 100 samples in estimated 5.7094 s (10k iterations)
Benchmarking oxcache_backend_switch/backend/memory: Analyzing
oxcache_backend_switch/backend/memory
                        time:   [2.0285 ms 2.1528 ms 2.2607 ms]
Benchmarking oxcache_backend_switch/backend/redis_mock
Benchmarking oxcache_backend_switch/backend/redis_mock: Warming up for 3.0000 s
Benchmarking oxcache_backend_switch/backend/redis_mock: Collecting 100 samples in estimated 5.9717 s (10k iterations)
Benchmarking oxcache_backend_switch/backend/redis_mock: Analyzing
oxcache_backend_switch/backend/redis_mock
                        time:   [2.1202 ms 2.2591 ms 2.3818 ms]

Benchmarking convert_placeholders/postgres
Benchmarking convert_placeholders/postgres: Warming up for 3.0000 s
Benchmarking convert_placeholders/postgres: Collecting 100 samples in estimated 5.0009 s (28M iterations)
Benchmarking convert_placeholders/postgres: Analyzing
convert_placeholders/postgres
                        time:   [179.19 ns 180.18 ns 181.35 ns]
Found 4 outliers among 100 measurements (4.00%)
  2 (2.00%) high mild
  2 (2.00%) high severe
Benchmarking convert_placeholders/sqlite_passthrough
Benchmarking convert_placeholders/sqlite_passthrough: Warming up for 3.0000 s
Benchmarking convert_placeholders/sqlite_passthrough: Collecting 100 samples in estimated 5.0000 s (713M iterations)
Benchmarking convert_placeholders/sqlite_passthrough: Analyzing
convert_placeholders/sqlite_passthrough
                        time:   [6.7209 ns 6.7298 ns 6.7391 ns]
Found 4 outliers among 100 measurements (4.00%)
  3 (3.00%) high mild
  1 (1.00%) high severe

Benchmarking circuit_execute_closed_passthrough
Benchmarking circuit_execute_closed_passthrough: Warming up for 3.0000 s
Benchmarking circuit_execute_closed_passthrough: Collecting 100 samples in estimated 5.0003 s (51M iterations)
Benchmarking circuit_execute_closed_passthrough: Analyzing
circuit_execute_closed_passthrough
                        time:   [97.082 ns 97.411 ns 97.788 ns]
Found 2 outliers among 100 measurements (2.00%)
  2 (2.00%) high mild

```

- criterion HTML：`target/criterion/`（不入库）
- 退出码：0
