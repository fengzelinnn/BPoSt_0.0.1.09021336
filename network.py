from data import FileChunk
from utils import log_msg


class Network:
    def __init__(self, nodes):
        self.nodes = nodes

    def gossip_upload(self, chunk: FileChunk):
        log_msg("DEBUG", "NETWORK", None, f"gossip chunk file={chunk.file_id} idx={chunk.index} to {len(self.nodes)} nodes")
        for n in self.nodes:
            n.receive_chunk(chunk)
