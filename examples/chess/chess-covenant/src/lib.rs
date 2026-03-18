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

pub fn vert_contract_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../sil/chess_vert.sil")
}

pub fn horiz_contract_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../sil/chess_horiz.sil")
}

pub fn diag_contract_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../sil/chess_diag.sil")
}

pub fn king_contract_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../sil/chess_king.sil")
}

pub fn castle_contract_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../sil/chess_castle.sil")
}
