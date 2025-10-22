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

性能监控通过 `bpst::monitoring::criterion` 模块采集 span 信息，并使用 Criterion 的 WallTime 计量器对执行时间进行统计分析。采集结果
可通过以下方式导出：

1. 设置导出环境变量并启动程序：
   ```bash
   BPST_CRITERION_CSV=criterion.csv \
   BPST_CRITERION_JSON=criterion.json \
   BPST_CRITERION_CLEAR=1 \
   cargo run -- node node-1 127.0.0.1 62000 none 1024 2097152 3
   ```
   - `BPST_CRITERION_CSV`：导出聚合统计为 CSV，包含均值、中位数与标准差（纳秒）。
   - `BPST_CRITERION_JSON`：导出与 CSV 同步的详细统计，便于集成自动化分析工具。
   - `BPST_CRITERION_CLEAR`：程序退出后是否清空内存数据（默认 `true`）。
2. 使用 `CriterionExportGuard` 会在程序结束时写出文件，并自动根据 span 层级聚合统计数据。
3. `consensus_pressure_report()` 会依据总执行时间计算根 span 的算力占比，方便定位性能热点。

## 清理监控数据

在需要重新采集数据时，可调用：
```rust
bpst::monitoring::criterion::monitor().clear();
```
或直接删除导出的 CSV/JSON 文件。

## 注意事项

- 当前实现基于 Criterion 的 WallTime 计量器，所有统计均以纳秒为单位。
- 若在生产环境部署，请确保程序具备写入 `BPST_CRITERION_*` 路径的权限。
