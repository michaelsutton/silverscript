use std::fs;

use blake2b_simd::Params;
use debugger_session::format_failure_report;
use debugger_session::session::{DebugEngine, DebugSession};
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{pay_to_script_hash_script, EngineCtx, EngineFlags, TxScriptEngine};
use kaspa_txscript_errors::TxScriptError;
use secp256k1::{Keypair, Secp256k1, SecretKey};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, CompileOptions, CompiledContract};

use chess_covenant::example_contract_path;

const COV_ID: Hash = Hash::from_bytes(*b"CHESSGAMECHESSGAMECHESSGAMECHESS");
const SLICE_CONCAT_REPRO_SOURCE: &str = r#"
contract SliceConcatRepro(byte[64] init_board) {
    byte[64] board = init_board;

    #[covenant.singleton(mode = transition)]
    function mv(byte[64] prev_board, int from_idx, int to_idx) : (byte[64]) {
        require(from_idx < to_idx);

        byte moving_piece = prev_board[from_idx];
        byte[] prev_dyn = byte[](prev_board);
        byte[] prefix = prev_dyn.slice(0, from_idx);
        byte[] middle = prev_dyn.slice(from_idx + 1, to_idx);
        byte[] suffix = prev_dyn.slice(to_idx + 1, 64);
        byte[] next_board_dyn = prefix + 0 + middle + moving_piece + suffix;
        int next_len = next_board_dyn.length;
        require(next_len == 64);
        byte[64] next_board = next_board_dyn;
        return(next_board);
    }
}
"#;
const SLICE_CONCAT_MANUAL_LOWERED_SOURCE: &str = r#"
contract SliceConcatManualLowered(byte[64] init_board) {
    byte[64] board = init_board;

    function covenant_policy_mv(byte[64] prev_board, int from_idx, int to_idx) : (byte[64]) {
        require(from_idx < to_idx);

        byte moving_piece = prev_board[from_idx];
        byte[] prev_dyn = byte[](prev_board);
        byte[] prefix = prev_dyn.slice(0, from_idx);
        byte[] middle = prev_dyn.slice(from_idx + 1, to_idx);
        byte[] suffix = prev_dyn.slice(to_idx + 1, 64);
        byte[] next_board_dyn = prefix + 0 + middle + moving_piece + suffix;
        int next_len = next_board_dyn.length;
        require(next_len == 64);
        byte[64] next_board = next_board_dyn;
        return(next_board);
    }

    entrypoint function mv(int from_idx, int to_idx) {
        int cov_out_count = OpAuthOutputCount(this.activeInputIndex);
        (byte[64] cov_new_board) = covenant_policy_mv(board, from_idx, to_idx);
        require(cov_out_count == 1);

        int cov_out_idx = OpAuthOutputIdx(this.activeInputIndex, 0);
        validateOutputState(cov_out_idx, {
            board: cov_new_board
        });
    }
}
"#;

struct Player {
    pubkey_bytes: Vec<u8>,
    pubkey_hash: Vec<u8>,
}

fn player_from_seed(seed: u8) -> Player {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[seed; 32]).expect("valid deterministic secret key");
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let (x_only, _) = keypair.x_only_public_key();
    let pubkey_bytes = x_only.serialize().to_vec();
    let pubkey_hash = Params::new().hash_length(32).to_state().update(&pubkey_bytes).finalize().as_bytes().to_vec();
    Player { pubkey_bytes, pubkey_hash }
}

fn load_chess_source() -> &'static str {
    let path = example_contract_path();
    let source = fs::read_to_string(path).unwrap_or_else(|err| panic!("failed to read {path}: {err}"));
    Box::leak(source.into_boxed_str())
}

fn standard_board() -> Vec<u8> {
    vec![
        0x04, 0x02, 0x03, 0x05, 0x06, 0x03, 0x02, 0x04, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x0c, 0x0a, 0x0b, 0x0d, 0x0e, 0x0b, 0x0a,
        0x0c,
    ]
}

fn move_piece(board: &mut [u8], from_x: usize, from_y: usize, to_x: usize, to_y: usize) {
    let from_idx = from_y * 8 + from_x;
    let to_idx = to_y * 8 + to_x;
    let piece = board[from_idx];
    board[from_idx] = 0x00;
    board[to_idx] = piece;
}

fn compile_state(
    source: &'static str,
    white_hash: &[u8],
    black_hash: &[u8],
    board: &[u8],
    turn: i64,
    status: i64,
) -> CompiledContract<'static> {
    let ctor = vec![
        Expr::bytes(white_hash.to_vec()),
        Expr::bytes(black_hash.to_vec()),
        Expr::bytes(board.to_vec()),
        Expr::int(turn),
        Expr::int(status),
    ];
    compile_contract(source, &ctor, CompileOptions::default()).expect("compile chess state")
}

fn covenant_sigscript(compiled: &CompiledContract<'_>, entrypoint: &str, args: Vec<Expr<'_>>) -> Vec<u8> {
    let mut sigscript = compiled.build_sig_script(entrypoint, args).expect("build sigscript");
    sigscript.extend_from_slice(&ScriptBuilder::new().add_data(&compiled.script).expect("push redeem script").drain());
    sigscript
}

fn tx_input(index: u32, signature_script: Vec<u8>) -> TransactionInput {
    TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([index as u8 + 1; 32]), index },
        signature_script,
        sequence: 0,
        sig_op_count: 0,
    }
}

fn covenant_output(compiled: &CompiledContract<'_>, authorizing_input: u16, covenant_id: Hash) -> TransactionOutput {
    TransactionOutput {
        value: 1_000,
        script_public_key: pay_to_script_hash_script(&compiled.script),
        covenant: Some(CovenantBinding { authorizing_input, covenant_id }),
    }
}

fn covenant_utxo(compiled: &CompiledContract<'_>, covenant_id: Hash) -> UtxoEntry {
    UtxoEntry::new(1_500, pay_to_script_hash_script(&compiled.script), 0, false, Some(covenant_id))
}

fn direct_script_output(compiled: &CompiledContract<'_>, authorizing_input: u16, covenant_id: Hash) -> TransactionOutput {
    TransactionOutput {
        value: 1_000,
        script_public_key: ScriptPublicKey::new(0, compiled.script.clone().into()),
        covenant: Some(CovenantBinding { authorizing_input, covenant_id }),
    }
}

fn direct_script_utxo(compiled: &CompiledContract<'_>, covenant_id: Hash) -> UtxoEntry {
    UtxoEntry::new(1_500, ScriptPublicKey::new(0, compiled.script.clone().into()), 0, false, Some(covenant_id))
}

fn execute_input_with_covenants(tx: Transaction, entries: Vec<UtxoEntry>, input_idx: usize) -> Result<(), TxScriptError> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);
    let input = tx.inputs[input_idx].clone();
    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = CovenantsContext::from_tx(&populated).map_err(TxScriptError::from)?;
    let utxo = populated.utxo(input_idx).expect("selected input utxo");

    let mut vm = TxScriptEngine::from_transaction_input(
        &populated,
        &input,
        input_idx,
        utxo,
        EngineCtx::new(&sig_cache).with_reused(&reused_values).with_covenants_ctx(&cov_ctx),
        EngineFlags { covenants_enabled: true },
    );
    vm.execute()
}

fn play_sigscript(
    active: &CompiledContract<'_>,
    player: &Player,
    from_x: i64,
    from_y: i64,
    to_x: i64,
    to_y: i64,
) -> Vec<u8> {
    covenant_sigscript(
        active,
        "play",
        vec![
            Expr::int(from_x),
            Expr::int(from_y),
            Expr::int(to_x),
            Expr::int(to_y),
            Expr::bytes(player.pubkey_bytes.clone()),
        ],
    )
}

fn assert_verify_like_error(err: TxScriptError) {
    assert!(matches!(err, TxScriptError::VerifyError | TxScriptError::EvalFalse), "expected verify/eval-false, got {err:?}");
}

fn assert_move_succeeds(
    label: &str,
    active: &CompiledContract<'_>,
    next: &CompiledContract<'_>,
    signer: &Player,
    from_x: i64,
    from_y: i64,
    to_x: i64,
    to_y: i64,
) {
    let outputs = vec![covenant_output(next, 0, COV_ID)];
    let entries = vec![covenant_utxo(active, COV_ID)];
    let sigscript = play_sigscript(active, signer, from_x, from_y, to_x, to_y);
    let signed_tx = Transaction::new(1, vec![tx_input(0, sigscript)], outputs, 0, Default::default(), 0, vec![]);

    let result = execute_input_with_covenants(signed_tx, entries, 0);
    assert!(result.is_ok(), "{label} should succeed: {:?}", result.unwrap_err());
}

#[test]
fn executes_several_chess_moves_with_covenant_context() {
    let source = load_chess_source();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let board0 = standard_board();
    let state0 = compile_state(source, &white.pubkey_hash, &black.pubkey_hash, &board0, 0, 0);

    let mut board1 = board0.clone();
    move_piece(&mut board1, 4, 1, 4, 3); // e2 -> e4
    let state1 = compile_state(source, &white.pubkey_hash, &black.pubkey_hash, &board1, 1, 0);
    assert_move_succeeds("e2->e4", &state0, &state1, &white, 4, 1, 4, 3);

    let mut board2 = board1.clone();
    move_piece(&mut board2, 4, 6, 4, 4); // e7 -> e5
    let state2 = compile_state(source, &white.pubkey_hash, &black.pubkey_hash, &board2, 0, 0);
    assert_move_succeeds("e7->e5", &state1, &state2, &black, 4, 6, 4, 4);

    let mut board3 = board2.clone();
    move_piece(&mut board3, 6, 0, 5, 2); // g1 -> f3
    let state3 = compile_state(source, &white.pubkey_hash, &black.pubkey_hash, &board3, 1, 0);
    assert_move_succeeds("g1->f3", &state2, &state3, &white, 6, 0, 5, 2);
}

#[test]
fn rejects_wrong_player_signature_for_current_turn() {
    let source = load_chess_source();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let board0 = standard_board();
    let mut board1 = board0.clone();
    move_piece(&mut board1, 4, 1, 4, 3); // e2 -> e4 already happened

    let active = compile_state(source, &white.pubkey_hash, &black.pubkey_hash, &board1, 1, 0); // black to move
    let mut board2 = board1.clone();
    move_piece(&mut board2, 4, 6, 4, 4); // expected black move output
    let out = compile_state(source, &white.pubkey_hash, &black.pubkey_hash, &board2, 0, 0);

    let outputs = vec![covenant_output(&out, 0, COV_ID)];
    let entries = vec![covenant_utxo(&active, COV_ID)];

    // Use white pubkey while it's black's turn.
    let wrong_sigscript = play_sigscript(&active, &white, 4, 6, 4, 4);
    let signed_tx = Transaction::new(1, vec![tx_input(0, wrong_sigscript)], outputs, 0, Default::default(), 0, vec![]);

    let err = execute_input_with_covenants(signed_tx, entries, 0).expect_err("wrong signer should fail");
    assert_verify_like_error(err);
}

#[test]
#[ignore = "known repro for transition slice+concat board construction"]
fn slice_concat_transition_repro_fails_validate_output_state() {
    let board0 = standard_board();
    let mut board1 = board0.clone();
    move_piece(&mut board1, 4, 1, 4, 3); // from_idx=12, to_idx=28

    let active =
        compile_contract(SLICE_CONCAT_REPRO_SOURCE, &[Expr::bytes(board0)], CompileOptions::default()).expect("compile active state");
    let out =
        compile_contract(SLICE_CONCAT_REPRO_SOURCE, &[Expr::bytes(board1)], CompileOptions::default()).expect("compile next state");

    let outputs = vec![covenant_output(&out, 0, COV_ID)];
    let entries = vec![covenant_utxo(&active, COV_ID)];
    let sigscript = covenant_sigscript(&active, "mv", vec![Expr::int(12), Expr::int(28)]);
    let tx = Transaction::new(1, vec![tx_input(0, sigscript)], outputs, 0, Default::default(), 0, vec![]);
    let result = execute_input_with_covenants(tx, entries, 0);

    assert!(result.is_ok(), "slice+concat transition should produce expected board, got {:?}", result.unwrap_err());
}

#[test]
#[ignore = "known repro for manual lowered transition slice+concat board construction"]
fn slice_concat_manual_lowered_repro_fails_validate_output_state() {
    let board0 = standard_board();
    let mut board1 = board0.clone();
    move_piece(&mut board1, 4, 1, 4, 3); // from_idx=12, to_idx=28

    let active = compile_contract(SLICE_CONCAT_MANUAL_LOWERED_SOURCE, &[Expr::bytes(board0)], CompileOptions::default())
        .expect("compile active state");
    let out = compile_contract(SLICE_CONCAT_MANUAL_LOWERED_SOURCE, &[Expr::bytes(board1)], CompileOptions::default())
        .expect("compile next state");

    let outputs = vec![covenant_output(&out, 0, COV_ID)];
    let entries = vec![covenant_utxo(&active, COV_ID)];
    let sigscript = covenant_sigscript(&active, "mv", vec![Expr::int(12), Expr::int(28)]);
    let tx = Transaction::new(1, vec![tx_input(0, sigscript)], outputs, 0, Default::default(), 0, vec![]);
    let result = execute_input_with_covenants(tx, entries, 0);

    assert!(result.is_ok(), "manual-lowered slice+concat transition should produce expected board, got {:?}", result.unwrap_err());
}

#[test]
#[ignore = "debug helper to locate failing source step for slice+concat repro"]
fn debug_slice_concat_repro_failure_line() {
    let board0 = standard_board();
    let mut board1 = board0.clone();
    move_piece(&mut board1, 4, 1, 4, 3); // from_idx=12, to_idx=28

    let compile_opts = CompileOptions { record_debug_infos: true, ..Default::default() };
    let active = compile_contract(SLICE_CONCAT_MANUAL_LOWERED_SOURCE, &[Expr::bytes(board0)], compile_opts)
        .expect("compile active state");
    let out = compile_contract(SLICE_CONCAT_MANUAL_LOWERED_SOURCE, &[Expr::bytes(board1)], compile_opts)
        .expect("compile next state");

    // Use direct lockscript execution to avoid P2SH stack plumbing in debugger session.
    let action_sigscript = active.build_sig_script("mv", vec![Expr::int(12), Expr::int(28)]).expect("build action sigscript");
    let input = tx_input(0, action_sigscript.clone());
    let outputs = vec![direct_script_output(&out, 0, COV_ID)];
    let tx = Transaction::new(1, vec![input], outputs, 0, Default::default(), 0, vec![]);
    let entries = vec![direct_script_utxo(&active, COV_ID)];
    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = CovenantsContext::from_tx(&populated).expect("build covenants context");
    let utxo = populated.utxo(0).expect("selected input utxo");
    let input_ref = &tx.inputs[0];

    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);
    let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values).with_covenants_ctx(&cov_ctx);
    let engine = DebugEngine::from_transaction_input(
        &populated,
        input_ref,
        0,
        utxo,
        ctx,
        EngineFlags { covenants_enabled: true },
    );

    let mut session = DebugSession::full(
        &action_sigscript,
        &active.script,
        SLICE_CONCAT_MANUAL_LOWERED_SOURCE,
        active.debug_info.clone(),
        engine,
    )
    .expect("create debug session");
    session.run_to_first_executed_statement().expect("reach first step");

    loop {
        match session.step_into() {
            Ok(Some(_)) => {}
            Ok(None) => panic!("script completed without failure"),
            Err(err) => {
                let report = session.build_failure_report(&err);
                let formatted = format_failure_report(&report, &|type_name, value| session.format_value(type_name, value));
                eprintln!("{formatted}");
                let frame = report.frames.first().expect("at least one failure frame");
                let span = frame.span.expect("failure frame has source span");
                panic!("debug located failure at line {} ({}-{})", span.line, span.col, span.end_col);
            }
        }
    }
}

#[test]
#[ignore = "debug helper to inspect concrete next_board_dyn.length in non-inlined context"]
fn debug_slice_concat_direct_next_len_value() {
    const LEN_PROBE_SOURCE: &str = r#"
contract LenProbe(byte[64] init_board) {
    byte[64] board = init_board;

    entrypoint function probe(int from_idx, int to_idx) {
        require(from_idx < to_idx);

        byte moving_piece = board[from_idx];
        byte[] prev_dyn = byte[](board);
        byte[] prefix = prev_dyn.slice(0, from_idx);
        byte[] middle = prev_dyn.slice(from_idx + 1, to_idx);
        byte[] suffix = prev_dyn.slice(to_idx + 1, 64);
        byte[] next_board_dyn = prefix + 0 + middle + moving_piece + suffix;
        int next_len = next_board_dyn.length;
        require(next_len == 64);
    }
}
"#;

    let board = standard_board();
    let compile_opts = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_contract(LEN_PROBE_SOURCE, &[Expr::bytes(board)], compile_opts).expect("compile probe");
    let sigscript = compiled
        .build_sig_script("probe", vec![Expr::int(12), Expr::int(28)])
        .expect("build probe sigscript");

    let input = tx_input(0, sigscript.clone());
    let outputs = vec![TransactionOutput {
        value: 1_000,
        script_public_key: ScriptPublicKey::new(0, vec![kaspa_txscript::opcodes::codes::OpTrue].into()),
        covenant: None,
    }];
    let tx = Transaction::new(1, vec![input], outputs, 0, Default::default(), 0, vec![]);
    let entries = vec![UtxoEntry::new(
        1_500,
        ScriptPublicKey::new(0, compiled.script.clone().into()),
        0,
        false,
        None,
    )];
    let populated = PopulatedTransaction::new(&tx, entries);
    let utxo = populated.utxo(0).expect("selected input utxo");
    let input_ref = &tx.inputs[0];

    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);
    let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values);
    let engine = DebugEngine::from_transaction_input(
        &populated,
        input_ref,
        0,
        utxo,
        ctx,
        EngineFlags { covenants_enabled: true },
    );

    let mut session = DebugSession::full(&sigscript, &compiled.script, LEN_PROBE_SOURCE, compiled.debug_info.clone(), engine)
        .expect("create debug session");
    session.run_to_first_executed_statement().expect("reach first step");

    loop {
        match session.step_into() {
            Ok(Some(_)) => {}
            Ok(None) => return,
            Err(err) => {
                let report = session.build_failure_report(&err);
                let formatted = format_failure_report(&report, &|type_name, value| session.format_value(type_name, value));
                eprintln!("{formatted}");
                let frame = report.frames.first().expect("at least one failure frame");
                let span = frame.span.expect("failure frame has source span");
                panic!("probe failure at line {} ({}-{})", span.line, span.col, span.end_col);
            }
        }
    }
}
