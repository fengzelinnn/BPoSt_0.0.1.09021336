#!/bin/bash
set -eu

# --- 核心配置参数 ---

# --- 实例总数 ---
TOTAL_INSTANCES=52

# --- 混合节点配置 ---
# 每个实例上部署的存储节点数量
STORAGE_NODES_PER_INSTANCE=4
# 每个实例上部署的用户节点数量
USER_NODES_PER_INSTANCE=1

# --- 基础目录 ---
BASE_DIR=$(pwd)/aws

# --- 脚本主逻辑 ---
echo "--- BPoSt 最终混合模式配置生成脚本 (引导节点修正版) ---"
echo "总实例数: ${TOTAL_INSTANCES}"
echo "每个实例的节点配置: ${STORAGE_NODES_PER_INSTANCE} 个存储节点 + ${USER_NODES_PER_INSTANCE} 个用户节点"
echo "--------------------------------"

# 清理并重建目录
rm -rf "${BASE_DIR}"
mkdir -p "${BASE_DIR}"

# --- 为所有实例生成混合配置文件 ---
echo ""
echo ">>> 开始为 ${TOTAL_INSTANCES} 个实例生成混合配置文件..."

for i in $(seq 1 "$TOTAL_INSTANCES"); do
  INSTANCE_DIR="${BASE_DIR}/instance-${i}"
  mkdir -p "$INSTANCE_DIR"

  # 1. 生成 config.template.json
  CONFIG_FILE="${INSTANCE_DIR}/config.template.json"
  {
    echo '{'
    echo '  "chunk_size": 1024, "min_file_kb": 8, "max_file_kb": 16, "bobtail_k": 25, "default_storage_kb": 8192, "min_storage_rounds": 7, "max_storage_rounds": 15,'
    echo '  "mining_difficulty_hex": "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",'
    
    # --- "nodes" 数组 (存储节点) ---
    echo '  "nodes": ['
    for j in $(seq 1 "$STORAGE_NODES_PER_INSTANCE"); do
      PORT=$((62000 + j - 1))
      echo '    {'
      echo "      \"node_id\": \"S${i}N${j}\","
      echo '      "host": "0.0.0.0",'
      echo "      \"port\": ${PORT},"
      echo '      "storage_kb": 8192, "bootstrap": "none", "peers": ['
      PEER_LIST=""
      # Peers: a) 同实例所有其他存储节点 b) 其他实例的第一个存储节点
      for p in $(seq 1 "$STORAGE_NODES_PER_INSTANCE"); do
        if [ "$p" -ne "$j" ]; then
          PEER_PORT=$((62000 + p - 1))
          PEER_LIST="${PEER_LIST}        { \"node_id\": \"S${i}N${p}\", \"host\": \"\${INSTANCE${i}_IP}\", \"port\": ${PEER_PORT} },"
        fi
      done
      for p in $(seq 1 "$TOTAL_INSTANCES"); do
          if [ "$p" -ne "$i" ]; then
              PEER_LIST="${PEER_LIST}        { \"node_id\": \"S${p}N1\", \"host\": \"\${INSTANCE${p}_IP}\", \"port\": 62000 },"
          fi
      done
      echo "${PEER_LIST%,}"
      echo '      ]'
      echo -n '    }'
      if [ "$j" -lt "$STORAGE_NODES_PER_INSTANCE" ]; then echo ','; else echo ''; fi
    done
    echo '  ],' # "nodes" 数组结束

    # --- "users" 数组 ---
    echo '  "users": ['
    for j in $(seq 1 "$USER_NODES_PER_INSTANCE"); do
      # 端口号紧跟在存储节点之后
      USER_NODE_PORT_OFFSET=$((STORAGE_NODES_PER_INSTANCE + j - 1))
      PORT=$((62000 + USER_NODE_PORT_OFFSET))
      echo '    {'
      echo "      \"user_id\": \"U${i}N${j}\","
      echo '      "host": "0.0.0.0",'
      echo "      \"port\": ${PORT},"
      # --- ✅ 核心修正: bootstrap 指向当前实例的第一个存储节点 ---
      echo "      \"bootstrap\": \"\${INSTANCE${i}_IP}:62000\""
      echo -n '    }'
      if [ "$j" -lt "$USER_NODES_PER_INSTANCE" ]; then echo ','; else echo ''; fi
    done
    echo '  ]' # "users" 数组结束

    echo '}' # 根对象结束
  } > "$CONFIG_FILE"

  # 2. 生成 docker-compose.yml
  DOCKER_COMPOSE_FILE="${INSTANCE_DIR}/docker-compose.yml"
  {
    echo 'services:'
    echo '  bc:'
    echo '    image: zelinfeng/bpost:latest'
    echo '    container_name: bc'
    echo '    environment:'
    echo "      BPST_ADVERTISE_IP: \${INSTANCE${i}_IP}"
    echo '      BPST_CONFIG_TEMPLATE: /etc/bpst/config.template.json'
    echo '      BPST_CONFIG_OUTPUT: /etc/bpst/deployment.json'
    echo '      BPST_CONFIG: /etc/bpst/deployment.json'
    for k in $(seq 1 "$TOTAL_INSTANCES"); do
      echo "      INSTANCE${k}_IP: \${INSTANCE${k}_IP}"
    done
    echo '    volumes:'
    echo '      - ./config.template.json:/etc/bpst/config.template.json:ro'
    echo '    restart: unless-stopped'
    echo '    command: ["deploy", "/etc/bpst/deployment.json"]'
    echo '    network_mode: "host"'
  } > "$DOCKER_COMPOSE_FILE"

  echo "  [OK] 已成功创建实例 #${i} 的混合配置: ${INSTANCE_DIR}"
done

echo ""
echo "--- ✅ 所有配置文件已生成完毕！ ---"
echo "文件已存放于: ${BASE_DIR}"