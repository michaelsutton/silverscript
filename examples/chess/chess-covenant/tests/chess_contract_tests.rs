use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::PopulatedTransaction;
use kaspa_txscript::parse_script;
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, CompileOptions};

use chess_covenant::{
    castle_challenge_contract_path, castle_contract_path, diag_contract_path, horiz_contract_path, king_contract_path,
    knight_contract_path, load_contract_source, mux_contract_path, pawn_contract_path, vert_contract_path,
};

#[test]
fn isolated_rook_path_loop_reports_script_size() {
    let source = isolated_rook_path_source();
    let compiled = compile_contract(source, &isolated_rook_path_constructor_args(5), CompileOptions::default())
        .expect("isolated rook path should compile");

    eprintln!("isolated_rook_path script_len={}", compiled.script.len());
    assert!(!compiled.script.is_empty());
}

#[test]
fn isolated_rook_path_loop_bound_sweep() {
    for bound in 1..=7 {
        let source = isolated_rook_path_source();
        match compile_contract(source, &isolated_rook_path_constructor_args(bound), CompileOptions::default()) {
            Ok(compiled) => eprintln!("isolated_rook_path bound={bound} script_len={}", compiled.script.len()),
            Err(err) => eprintln!("isolated_rook_path bound={bound} compile_error={err}"),
        }
    }
}

#[test]
fn chess_pawn_reports_script_size_and_opcode_count() {
    let path = pawn_contract_path();
    let source = load_contract_source(path);
    let compiled =
        compile_contract(&source, &pawn_constructor_args(), CompileOptions::default()).expect("pawn contract should compile");
    let opcode_count = parse_script::<PopulatedTransaction<'static>, SigHashReusedValuesUnsync>(&compiled.script).count();

    eprintln!("chess_pawn script_len={} opcode_count={}", compiled.script.len(), opcode_count);
    assert!(!compiled.script.is_empty());
}

#[test]
fn chess_mux_reports_script_size_and_opcode_count() {
    let path = mux_contract_path();
    let source = load_contract_source(path);
    let compiled = compile_contract(&source, &mux_constructor_args(), CompileOptions::default()).expect("mux contract should compile");
    let opcode_count = parse_script::<PopulatedTransaction<'static>, SigHashReusedValuesUnsync>(&compiled.script).count();

    eprintln!("chess_mux script_len={} opcode_count={}", compiled.script.len(), opcode_count);
    assert!(!compiled.script.is_empty());
}

#[test]
fn chess_workers_report_script_size_and_opcode_count() {
    let workers = [
        ("knight", knight_contract_path()),
        ("king", king_contract_path()),
        ("vert", vert_contract_path()),
        ("horiz", horiz_contract_path()),
        ("diag", diag_contract_path()),
        ("castle", castle_contract_path()),
        ("castle_challenge", castle_challenge_contract_path()),
    ];

    for (name, path) in workers {
        let source = load_contract_source(path);
        let compiled = compile_contract(&source, &pawn_constructor_args(), CompileOptions::default()).expect("worker should compile");
        let opcode_count = parse_script::<PopulatedTransaction<'static>, SigHashReusedValuesUnsync>(&compiled.script).count();
        eprintln!("{name} script_len={} opcode_count={}", compiled.script.len(), opcode_count);
    }
}

fn isolated_rook_path_source() -> &'static str {
    r#"
pragma silverscript ^0.1.0;

contract Probe(byte[64] init_board, int path_bound) {
    byte[64] board = init_board;

    function rook_path_clear(
        byte[64] board_data,
        int from_x,
        int from_y,
        int to_x,
        int to_y
    ) : (int) {
        int step_x = 0;
        if (to_x > from_x) {
            step_x = 1;
        } else if (to_x < from_x) {
            step_x = -1;
        }

        int step_y = 0;
        if (to_y > from_y) {
            step_y = 1;
        } else if (to_y < from_y) {
            step_y = -1;
        }

        int x = from_x + step_x;
        int y = from_y + step_y;
        int clear = 1;

        for (i, 0, path_bound, path_bound) {
            bool at_target = x == to_x && y == to_y;
            if (clear == 1 && !at_target) {
                int idx = y * 8 + x;
                if (OpBin2Num(board_data[idx]) != 0) {
                    clear = 0;
                }
                x = x + step_x;
                y = y + step_y;
            }
        }

        return(clear);
    }

    entrypoint function main() {
        byte[64] board_data = board;
        (int clear) = rook_path_clear(board_data, 0, 0, 0, 7);
        require(clear == 0 || clear == 1);
    }
}
"#
}

fn isolated_rook_path_constructor_args(bound: usize) -> Vec<Expr<'static>> {
    vec![Expr::bytes(vec![0u8; 64]), Expr::int(bound as i64)]
}

fn pawn_constructor_args() -> Vec<Expr<'static>> {
    let standard_board: Vec<u8> = vec![
        0x04, 0x02, 0x03, 0x05, 0x06, 0x03, 0x02, 0x04, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x0c, 0x0a, 0x0b, 0x0d, 0x0e, 0x0b, 0x0a,
        0x0c,
    ];
    let mut route_hashes = Vec::with_capacity(32 * 8);
    for byte in 0x12u8..=0x19u8 {
        route_hashes.extend_from_slice(&[byte; 32]);
    }

    vec![
        Expr::bytes(vec![0x11u8; 32]),
        Expr::bytes(route_hashes),
        Expr::bytes(vec![0x21u8; 32]),
        Expr::bytes(vec![0x22u8; 32]),
        Expr::bytes(standard_board),
        Expr::int(0),
        Expr::int(0),
        Expr::bytes(vec![1u8; 4]),
        Expr::int(-1),
        Expr::int(12),
        Expr::int(28),
        Expr::int(0),
        Expr::int(0),
        Expr::int(3),
    ]
}

fn mux_constructor_args() -> Vec<Expr<'static>> {
    let mut route_hashes = Vec::with_capacity(32 * 8);
    for byte in 0x12u8..=0x19u8 {
        route_hashes.extend_from_slice(&[byte; 32]);
    }

    vec![
        Expr::bytes(vec![0x11u8; 32]),
        Expr::bytes(route_hashes),
        Expr::bytes(vec![0x21u8; 32]),
        Expr::bytes(vec![0x22u8; 32]),
        Expr::bytes(vec![0u8; 64]),
        Expr::int(0),
        Expr::int(0),
        Expr::bytes(vec![1u8; 4]),
        Expr::int(-1),
        Expr::int(-1),
        Expr::int(-1),
        Expr::int(0),
        Expr::int(0),
        Expr::int(3),
    ]
}
