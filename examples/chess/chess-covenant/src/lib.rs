pub mod model;

pub fn example_contract_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../sil/chess_game.sil")
}

pub fn mux_contract_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../sil/chess_mux.sil")
}

pub fn pawn_contract_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../sil/chess_pawn.sil")
}

pub fn knight_contract_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../sil/chess_knight.sil")
}

pub fn file_up_contract_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../sil/chess_file_up.sil")
}

pub fn file_down_contract_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../sil/chess_file_down.sil")
}

pub fn rank_left_contract_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../sil/chess_rank_left.sil")
}

pub fn rank_right_contract_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../sil/chess_rank_right.sil")
}

pub fn diag_up_right_contract_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../sil/chess_diag_up_right.sil")
}

pub fn diag_up_left_contract_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../sil/chess_diag_up_left.sil")
}

pub fn diag_down_right_contract_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../sil/chess_diag_down_right.sil")
}

pub fn diag_down_left_contract_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../sil/chess_diag_down_left.sil")
}

pub fn king_contract_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../sil/chess_king.sil")
}
