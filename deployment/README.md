# Docker 部署指南

本目录提供了在 Linux 服务器上使用 Docker 一次性部署多个 BPoSt 节点的模板。部署时可显式指定每个节点监听的 IP、端口、存储容量、文件大小范围以及挖矿难度，避免再依赖额外的节点发现逻辑。

## 目录结构

- `config.example.json`：示例部署配置文件，定义存储节点、用户节点、观察者节点以及全局参数。
- `docker-compose.yml`：使用单个容器运行集群的示例，容器内部由二进制的 `deploy` 子命令启动全部子进程。
- `entrypoint.sh`：容器入口脚本，支持直接运行 `deploy` 配置，也支持基于环境变量启动单个节点。

## 构建镜像

在项目根目录执行：

```bash
docker build -t bpst:latest .
```

镜像会在构建阶段编译 release 版本的二进制，并在运行时使用精简的 Debian 容器。

## 使用部署配置一次性启动全部进程

1. 根据部署需要复制示例配置：
   ```bash
   cp deployment/config.example.json deployment/config.json
   ```
2. 编辑 `deployment/config.json`，为每个节点填写实际的 `host` 与 `port`（应使用服务器的对外 IP），以及可选的 `storage_kb`、`chunk_size`、`bobtail_k`、`mining_difficulty_hex` 等参数。
   - `min_file_kb` / `max_file_kb` 决定文件生成的大小范围。
   - `mining_difficulty_hex` 以 16 进制字符串指定全局挖矿难度，单个节点也可以通过 `nodes[*].mining_difficulty_hex` 覆盖。
3. 根据节点暴露的端口调整 `deployment/docker-compose.yml` 中的 `ports` 映射。
4. 启动：
   ```bash
   cd deployment
   docker compose up -d
   ```

容器会在启动后执行 `bpst deploy /etc/bpst/deployment.json`，并在日志中打印每个子进程的 IP、端口、文件大小、挖矿难度等信息。配置中的第一个存储节点默认作为引导节点，其余节点自动连接到该地址；若需要自定义，可在节点条目中设置 `"bootstrap"` 字段（支持 `none`）。

## 通过环境变量启动单个节点

若希望在同一服务器上以多个容器分别运行单个节点，可使用入口脚本的 `BPST_ROLE` 模式：

```bash
docker run --rm \
  -e BPST_ROLE=node \
  -e BPST_NODE_ID=S0 \
  -e BPST_HOST=0.0.0.0 \
  -e BPST_PORT=62000 \
  -e BPST_BOOTSTRAP=none \
  -e BPST_CHUNK_SIZE=1024 \
  -e BPST_STORAGE_KB=4096 \
  -e BPST_BOBTAIL_K=3 \
  -e BPST_MINING_DIFFICULTY_HEX=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  -p 62000:62000 \
  bpst:latest
```

支持的角色与必须变量：

| 角色 (`BPST_ROLE`) | 必填变量 | 说明 |
| --- | --- | --- |
| `node` | `BPST_NODE_ID`, `BPST_HOST`, `BPST_PORT` | 其他可选：`BPST_BOOTSTRAP`、`BPST_CHUNK_SIZE`、`BPST_STORAGE_KB`、`BPST_BOBTAIL_K`、`BPST_MINING_DIFFICULTY_HEX` |
| `user` | `BPST_USER_ID`, `BPST_HOST`, `BPST_PORT` | 可选：`BPST_BOOTSTRAP`（默认为 `127.0.0.1:62000`） |
| `observer` | `BPST_OBSERVER_ID`, `BPST_HOST`, `BPST_PORT` | 可选：`BPST_BOOTSTRAP`（默认为 `127.0.0.1:62000`） |

若容器既没有命令参数也未设置 `BPST_ROLE`，则默认运行 `bpst` 主程序原有的模拟流程。

## 日志与状态

- 部署过程中会输出每个子进程监听的 IP/端口、文件大小范围、挖矿难度阈值，便于在多服务器场景下登记与共享。
- 按下 `Ctrl+C` 或向容器发送 `SIGTERM` 时，`deploy` 命令会优雅地终止所有子进程。

## 自定义配置格式

部署配置文件使用 JSON 格式，对应 `src/config.rs` 中的 `DeploymentConfig` 结构：

```json
{
  "chunk_size": 1024,
  "min_file_kb": 16,
  "max_file_kb": 64,
  "bobtail_k": 3,
  "default_storage_kb": 4096,
  "mining_difficulty_hex": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "nodes": [
    {
      "node_id": "S0",
      "host": "203.0.113.10",
      "port": 62000,
      "bootstrap": "none"
    },
    {
      "node_id": "S1",
      "host": "203.0.113.10",
      "port": 62001,
      "storage_kb": 6144,
      "mining_difficulty_hex": "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    }
  ],
  "users": [
    {
      "user_id": "U0",
      "host": "203.0.113.11",
      "port": 62010,
      "bootstrap": "203.0.113.10:62000"
    }
  ],
  "observer": {
    "observer_id": "OBS0",
    "host": "203.0.113.12",
    "port": 62020,
    "bootstrap": "203.0.113.10:62000"
  }
}
```

- `nodes` 中首个条目默认作为引导节点；其 `bootstrap` 可留空或设置为 `"none"`。
- 其余节点若未指定 `bootstrap`，会自动指向首个节点的地址。
- `users`、`observer` 的 `bootstrap` 必须是有效的 `ip:port`，若省略则使用第一个节点的地址。

通过上述配置即可在一个服务器上部署多个节点，并将监听地址（IP/端口）、文件大小范围与挖矿难度显式暴露给其他服务器或调度系统。
