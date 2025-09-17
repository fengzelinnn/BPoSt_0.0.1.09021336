use bpst::config::P2PSimConfig;
use bpst::simulation::run_p2p_simulation;

fn main() {
    let config = P2PSimConfig {
        num_nodes: 15,
        num_file_owners: 7,
        sim_duration_sec: 9000,
        chunk_size: 16,
        min_file_kb: 1,
        max_file_kb: 2,
        min_storage_nodes: 4,
        max_storage_nodes: 5,
        base_port: 62000,
        bobtail_k: 3,
        min_storage_kb: 512,
        max_storage_kb: 2048,
        bid_wait_sec: 20,
    };
    run_p2p_simulation(config);
}
