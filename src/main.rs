use bpst::config::P2PSimConfig;
use bpst::simulation::{
    run_node_process_from_args, run_p2p_simulation, run_user_process_from_args,
};

fn main() {
    let mut args = std::env::args();
    let _exe = args.next();
    if let Some(subcommand) = args.next() {
        match subcommand.as_str() {
            "node" => {
                run_node_process_from_args(args);
                return;
            }
            "user" => {
                run_user_process_from_args(args);
                return;
            }
            _ => {}
        }
    }
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
