use std::fs;

use blake2b_simd::Params;
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry, VerifiableTransaction,
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
    proposed_board: Vec<u8>,
) -> Vec<u8> {
    covenant_sigscript(
        active,
        "play",
        vec![
            Expr::int(from_x),
            Expr::int(from_y),
            Expr::int(to_x),
            Expr::int(to_y),
            Expr::bytes(proposed_board),
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
    next_board: &[u8],
    signer: &Player,
    from_x: i64,
    from_y: i64,
    to_x: i64,
    to_y: i64,
) {
    let outputs = vec![covenant_output(next, 0, COV_ID)];
    let entries = vec![covenant_utxo(active, COV_ID)];
    let sigscript = play_sigscript(active, signer, from_x, from_y, to_x, to_y, next_board.to_vec());
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
    assert_move_succeeds("e2->e4", &state0, &state1, &board1, &white, 4, 1, 4, 3);

    let mut board2 = board1.clone();
    move_piece(&mut board2, 4, 6, 4, 4); // e7 -> e5
    let state2 = compile_state(source, &white.pubkey_hash, &black.pubkey_hash, &board2, 0, 0);
    assert_move_succeeds("e7->e5", &state1, &state2, &board2, &black, 4, 6, 4, 4);

    let mut board3 = board2.clone();
    move_piece(&mut board3, 6, 0, 5, 2); // g1 -> f3
    let state3 = compile_state(source, &white.pubkey_hash, &black.pubkey_hash, &board3, 1, 0);
    assert_move_succeeds("g1->f3", &state2, &state3, &board3, &white, 6, 0, 5, 2);
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
    let wrong_sigscript = play_sigscript(&active, &white, 4, 6, 4, 4, board2);
    let signed_tx = Transaction::new(1, vec![tx_input(0, wrong_sigscript)], outputs, 0, Default::default(), 0, vec![]);

    let err = execute_input_with_covenants(signed_tx, entries, 0).expect_err("wrong signer should fail");
    assert_verify_like_error(err);
}
