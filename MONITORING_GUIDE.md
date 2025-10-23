# 运行与性能监控指引

本指南介绍如何启动 BPoSt 项目、运行基准测试，并导出性能监控结果。示例命令默认在项目根目录执行。

## 运行节点模拟

1. 构建项目：
   ```bash
   cargo build
   ```
2. 运行默认的 P2P 模拟：
   ```bash
   cargo run
   ```
3. 以子命令方式启动特定角色（示例）：
   ```bash
   # 启动单个节点进程（参数依次为：节点ID、监听IP、监听端口、引导地址或 none、数据块大小、最大存储字节、bobtail_k）
   cargo run -- node node-1 127.0.0.1 62000 none 1024 2097152 3

   # 启动单个用户进程（参数依次为：用户ID、监听IP、监听端口、引导节点地址）
   cargo run -- user user-1 127.0.0.1 62010 127.0.0.1:62000

   # 基于部署配置文件启动
   cargo run -- deploy ./deployment/config.json
   ```
   - 若需要连接现有节点，将 `none` 替换为形如 `127.0.0.1:62000` 的引导节点地址。
   - `最大存储字节` 示例中取值为 2 MiB (`2048 * 1024`)。

## 基准测试 dPDP 与 Folding

1. 预先构建基准测试所需依赖：
   ```bash
   cargo bench --no-run
   ```
2. 执行全部 Criterion 基准：
   ```bash
   cargo bench
   ```
3. 若只需运行指定基准，可使用 Criterion 的过滤功能：
   ```bash
   cargo bench -- dpdp
   cargo bench -- folding
   ```

基准完成后，Criterion 会在 `target/criterion` 目录生成详细报告，可通过浏览器打开相应的 `report/index.html`。

## 查看性能监控数据

性能监控通过 `bpst::monitoring::flamegraph` 模块自动采集 Span 信息，并以 `cargo flamegraph` 兼容的方式展示 CPU 开销。可通过以下方式导出：

1. 设置导出环境变量并启动程序：
   ```bash
   BPST_FLAME_COLLAPSED=perf.folded \
   BPST_FLAME_HTML=perf.html \
   BPST_FLAME_CLEAR=1 \
   cargo run -- node node-1 127.0.0.1 62000 none 1024 2097152 3
   ```
   - `BPST_FLAME_COLLAPSED`：导出折叠栈文本，可直接交给 `cargo flamegraph` 渲染。
   - `BPST_FLAME_HTML`：导出交互式 HTML 火焰图，便于本地分析。
   - `BPST_FLAME_CLEAR`：程序退出后是否清空内存数据（默认 `true`）。
   - 仍向后兼容旧的 `BPST_PERF_*` 环境变量，但建议迁移到新的命名。
2. 使用 `FlamegraphExportGuard` 会在程序结束时写出上述文件，并在需要时自动清理内存中的采集结果。
3. `consensus_pressure_report()` 基于采集到的纳秒耗时计算根 Span 的算力占比。

## 清理监控数据

在需要重新采集数据时，可调用：
```rust
bpst::monitoring::flamegraph::monitor().clear();
```
或直接删除导出的折叠栈与 HTML 文件。

## 注意事项

- 若在生产环境部署，请确保程序具备写入 `BPST_FLAME_*` 路径的权限。
