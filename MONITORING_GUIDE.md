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
   cargo run -- node
   cargo run -- user
   cargo run -- deploy ./deployment/config.json
   ```

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

性能监控通过 `bpst::monitoring::perf` 模块自动采集 Span 信息，并在 Windows 上使用 `QueryThreadCycleTime` 记录 CPU cycle。采集结果可通过以下方式导出：

1. 设置导出环境变量并启动程序：
   ```bash
   BPST_PERF_CSV=perf.csv \
   BPST_PERF_FLAME=perf.svg \
   BPST_PERF_CLEAR=1 \
   cargo run -- node
   ```
   - `BPST_PERF_CSV`：导出记录为 CSV。
   - `BPST_PERF_FLAME`：导出压缩火焰图（SVG）。
   - `BPST_PERF_CLEAR`：程序退出后是否清空内存数据（默认 `true`）。
2. 使用 `PerfExportGuard` 会在程序结束时写出文件，并将 CSV 中的 `cpu_cycles` 与 `instructions_est` 列对齐。
3. `consensus_pressure_report()` 会优先以 CPU cycle 计算各根 Span 的算力占比，当 cycle 不可用时回退到纳秒时长。

## 清理监控数据

在需要重新采集数据时，可调用：
```rust
bpst::monitoring::perf::monitor().clear();
```
或直接删除导出的 CSV/SVG 文件。

## 注意事项

- 在非 Windows 平台上，系统将回退到 `_rdtsc` 指令或执行时间统计，仍可生成压力分布报告。
- 若在生产环境部署，请确保程序具备写入 `BPST_PERF_*` 路径的权限。
