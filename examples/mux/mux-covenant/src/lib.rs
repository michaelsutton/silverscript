pub fn mux_contract_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../sil/mux.sil")
}

pub fn worker_a_contract_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../sil/A.sil")
}

pub fn worker_b_contract_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../sil/B.sil")
}
