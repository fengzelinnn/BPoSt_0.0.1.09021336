# Docker 部署指南

本目录提供了在 Linux 服务器上使用 Docker 构建与运行 BPoSt 集群的模板。新的配置以云环境为目标，预留了显式指定公网 IP 的位置，同时在本地测试时默认使用 `127.0.0.1`。

## 目录结构

- `config.template.json`：部署模板，`entrypoint.sh` 会根据环境变量将其中的占位符替换为真实 IP 后生成最终配置。
- `config.example.json`：使用 `127.0.0.1` 渲染后的示例配置，便于离线查看字段含义。
- `docker-compose.yml`：单容器运行完整集群的 Compose 示例。
- `entrypoint.sh`：容器入口脚本，会在启动时渲染模板并运行相应的子命令。

## 构建镜像

在项目根目录执行：

```bash
docker build -t bpst:latest .
```

镜像使用最新的 Rust 稳定版进行构建，运行阶段基于 `debian:bookworm-slim` 并附带 `gettext-base` 以支持模板渲染。

## 使用模板一次性启动全部进程

1. 根据部署需要复制或修改 `config.template.json`。模板中所有 `\${BPST_...}` 字段会在容器启动时被替换：
   - `BPST_ADVERTISE_IP`：各节点对外公布的地址，默认值为 `127.0.0.1`，部署到云服务器时将其设置为服务器公网 IP。
   - `BPST_BOOTSTRAP_IP`：用户与观察者连接的引导地址，默认与 `BPST_ADVERTISE_IP` 相同。
2. 启动：
   ```bash
   cd deployment
   docker compose up -d
   ```

   `docker-compose.yml` 会把模板挂载到容器内的 `/etc/bpst/config.template.json`，入口脚本会在启动时渲染为 `/etc/bpst/deployment.json` 并执行 `bpst deploy`。

3. 若要在多台服务器之间复用该模板，可在部署前通过 `.env` 或环境变量覆盖 `BPST_ADVERTISE_IP` / `BPST_BOOTSTRAP_IP`：
   ```bash
   BPST_ADVERTISE_IP=203.0.113.10 \
   BPST_BOOTSTRAP_IP=203.0.113.10 \
   docker compose up -d
   ```

   如需为部分节点指定不同 IP，可直接编辑模板中对应节点的 `host` 字段。

## 通过环境变量启动单个节点

入口脚本仍然支持旧的单节点模式，可在多容器部署时使用：

```bash
docker run --rm \
  -e BPST_ROLE=node \
  -e BPST_NODE_ID=S0 \
  -e BPST_HOST=0.0.0.0 \
  -e BPST_PORT=62000 \
  -e BPST_BOOTSTRAP_IP=203.0.113.10 \
  -e BPST_STORAGE_KB=4096 \
  -p 62000:62000 \
  bpst:latest
```

支持的角色与必须变量：

| 角色 (`BPST_ROLE`) | 必填变量 | 说明 |
| --- | --- | --- |
| `node` | `BPST_NODE_ID`, `BPST_HOST`, `BPST_PORT` | 其他可选：`BPST_BOOTSTRAP`、`BPST_CHUNK_SIZE`、`BPST_STORAGE_KB`、`BPST_BOBTAIL_K`、`BPST_MINING_DIFFICULTY_HEX` |
| `user` | `BPST_USER_ID`, `BPST_HOST`, `BPST_PORT` | 可选：`BPST_BOOTSTRAP`（默认使用 `BPST_BOOTSTRAP_IP:62000`） |
| `observer` | `BPST_OBSERVER_ID`, `BPST_HOST`, `BPST_PORT` | 可选：`BPST_BOOTSTRAP`（默认使用 `BPST_BOOTSTRAP_IP:62000`） |

当既未提供命令参数也没有 `BPST_ROLE` 时，脚本会使用渲染后的配置执行 `bpst deploy`，若配置缺失则回退到运行主程序默认流程。

## 日志与状态

- 启动时会打印模板渲染后的配置路径，便于排查。
- 终止容器或发送 `SIGTERM` 时，`deploy` 命令会优雅关闭所有子进程。

## 自定义配置格式

部署配置文件为 JSON，字段与 `src/config.rs` 中的 `DeploymentConfig` 结构对应。可以在模板中使用任意 `\${...}` 占位符，以便通过环境变量或外部工具统一替换，从而适应多云服务器部署场景。
