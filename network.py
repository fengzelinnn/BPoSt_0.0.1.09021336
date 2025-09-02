from data import FileChunk
from utils import log_msg

try:
    import simpy
except ImportError:  # soft dependency; required for simulation mode
    simpy = None


class Network:
    def __init__(self, nodes, env: 'simpy.Environment' = None, per_hop_delay: float = 0.001):
        self.nodes = nodes
        self.env = env
        self.per_hop_delay = per_hop_delay  # simulated broadcast latency per recipient

    def bind_env(self, env: 'simpy.Environment'):
        self.env = env
        return self

    def gossip_upload(self, chunk: FileChunk):
        """Instant (legacy) broadcast to all nodes (kept for demo())."""
        log_msg("DEBUG", "NETWORK", None, f"gossip chunk file={chunk.file_id} idx={chunk.index} to {len(self.nodes)} nodes (instant)")
        for n in self.nodes:
            n.receive_chunk(chunk)

    def gossip_upload_proc(self, chunk: FileChunk):
        """SimPy process: gossip the chunk to all nodes with simulated delay.
        Yields env.timeout for each hop to model network latency.
        """
        if self.env is None:
            # Fallback to instant if env not set
            return self.gossip_upload(chunk)
        log_msg("DEBUG", "NETWORK", None, f"[t={self.env.now}] start gossip file={chunk.file_id} idx={chunk.index} to {len(self.nodes)} nodes")
        for i, n in enumerate(self.nodes):
            yield self.env.timeout(self.per_hop_delay)
            n.receive_chunk(chunk)
            log_msg("DEBUG", "NETWORK", None, f"[t={self.env.now}] delivered file={chunk.file_id} idx={chunk.index} to {n.node_id} (#{i+1})")
        log_msg("INFO", "NETWORK", None, f"[t={self.env.now}] gossip complete file={chunk.file_id} idx={chunk.index}")
