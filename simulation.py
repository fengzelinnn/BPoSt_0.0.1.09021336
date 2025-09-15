import multiprocessing
import time
import random

from config import P2PSimConfig
from p2p.node import Node
from p2p.user_node import UserNode
from roles.file_owner import FileOwner
from utils import log_msg

def run_p2p_simulation(config: P2PSimConfig):
    """运行BPoSt P2P网络的全功能模拟。"""
    log_msg("INFO", "SIMULATOR", "MAIN", f"正在使用配置启动模拟: {config}")

    manager = multiprocessing.Manager()
    report_queue = manager.Queue()
    
    stop_events = []
    all_procs = []
    
    bootstrap_addr = ("localhost", config.base_port)
    current_port = config.base_port

    # 创建存储节点
    for i in range(config.num_nodes):
        port = current_port
        current_port += 1
        node_capacity = random.randint(config.min_storage_kb, config.max_storage_kb) * 1024
        
        stop_event = manager.Event()
        p2p_node = Node(
            node_id=f"S{i}",
            host="localhost",
            port=port,
            bootstrap_addr=bootstrap_addr if i > 0 else None,
            chunk_size=config.chunk_size,
            max_storage=node_capacity,
            bobtail_k=config.bobtail_k,
            stop_event=stop_event,
            report_queue=report_queue
        )
        stop_events.append(stop_event)
        all_procs.append(p2p_node)

    # 创建用户节点
    for i in range(config.num_file_owners):
        port = current_port
        current_port += 1
        file_owner = FileOwner(f"U{i}", config.chunk_size)
        
        stop_event = manager.Event()
        user_node = UserNode(
            owner=file_owner, 
            host="localhost", 
            port=port,
            bootstrap_addr=bootstrap_addr,
            config=config,
            stop_event=stop_event
        )
        stop_events.append(stop_event)
        all_procs.append(user_node)

    for proc in all_procs:
        proc.start()
        time.sleep(0.05)

    log_msg("INFO", "SIMULATOR", "MAIN", f"已启动 {config.num_nodes} 个存储节点和 {config.num_file_owners} 个用户节点。")
    log_msg("INFO", "SIMULATOR", "MAIN", f"共识和存储模拟将运行 {config.sim_duration_sec} 秒...")

    try:
        time.sleep(config.sim_duration_sec)
    except KeyboardInterrupt:
        log_msg("INFO", "SIMULATOR", "MAIN", "检测到手动中断。正在停止...")

    log_msg("INFO", "SIMULATOR", "MAIN", "模拟时间结束。正在停止节点并分析结果...")
    for event in stop_events:
        event.set()
    for proc in all_procs:
        proc.join(timeout=5)

    log_msg("INFO", "SIMULATOR", "MAIN", "模拟结束。")
