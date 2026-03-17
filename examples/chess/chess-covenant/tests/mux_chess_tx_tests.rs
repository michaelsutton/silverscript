use std::fs;

use blake2b_simd::Params as Blake2bParams;
use kaspa_consensus_core::hashing::sighash::calc_schnorr_signature_hash;
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry, VerifiableTransaction,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::{pay_to_script_hash_script, pay_to_script_hash_signature_script, EngineCtx, EngineFlags, TxScriptEngine};
use kaspa_txscript_errors::TxScriptError;
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, CompileOptions, CompiledContract};

use chess_covenant::{knight_contract_path, mux_contract_path, pawn_contract_path};

struct Player {
    keypair: Keypair,
    pubkey_bytes: Vec<u8>,
    pubkey_hash: Vec<u8>,
}

struct MuxChessFixture {
    mux_source: &'static str,
    pawn_source: &'static str,
    knight_source: &'static str,
    mux_prefix: Vec<u8>,
    mux_suffix: Vec<u8>,
    mux_hash: Vec<u8>,
    pawn_prefix: Vec<u8>,
    pawn_suffix: Vec<u8>,
    pawn_hash: Vec<u8>,
    knight_prefix: Vec<u8>,
    knight_suffix: Vec<u8>,
    knight_hash: Vec<u8>,
}

fn player_from_seed(seed: u8) -> Player {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[seed; 32]).expect("valid deterministic secret key");
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let (x_only, _) = keypair.x_only_public_key();
    let pubkey_bytes = x_only.serialize().to_vec();
    let pubkey_hash = Blake2bParams::new().hash_length(32).to_state().update(&pubkey_bytes).finalize().as_bytes().to_vec();
    Player { keypair, pubkey_bytes, pubkey_hash }
}

fn load_contract_source(path: &'static str) -> &'static str {
    let source = fs::read_to_string(path).unwrap_or_else(|err| panic!("failed to read {path}: {err}"));
    Box::leak(source.into_boxed_str())
}

fn template_parts_and_hash(source: &str, state: &[Expr<'_>]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let compiled = compile_contract(source, state, CompileOptions::default()).expect("compile template source succeeds");
    let layout = compiled.state_layout;
    let prefix = compiled.script[..layout.start].to_vec();
    let suffix = compiled.script[layout.start + layout.len..].to_vec();
    let hash = Blake2bParams::new().hash_length(32).to_state().update(&prefix).update(&suffix).finalize().as_bytes().to_vec();
    (prefix, suffix, hash)
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

fn build_fixture() -> MuxChessFixture {
    let mux_source = load_contract_source(mux_contract_path());
    let pawn_source = load_contract_source(pawn_contract_path());
    let knight_source = load_contract_source(knight_contract_path());

    let dummy_player_a = vec![0x11u8; 32];
    let dummy_player_b = vec![0x22u8; 32];
    let dummy_board = standard_board();
    let ctor = [
        vec![0x31u8; 32].into(),
        vec![0x41u8; 32].into(),
        vec![0x51u8; 32].into(),
        dummy_player_a.into(),
        dummy_player_b.into(),
        dummy_board.into(),
        0.into(),
        0.into(),
    ];

    let (mux_prefix, mux_suffix, mux_hash) = template_parts_and_hash(mux_source, &ctor);
    let (pawn_prefix, pawn_suffix, pawn_hash) = template_parts_and_hash(pawn_source, &ctor);
    let (knight_prefix, knight_suffix, knight_hash) = template_parts_and_hash(knight_source, &ctor);

    MuxChessFixture {
        mux_source,
        pawn_source,
        knight_source,
        mux_prefix,
        mux_suffix,
        mux_hash,
        pawn_prefix,
        pawn_suffix,
        pawn_hash,
        knight_prefix,
        knight_suffix,
        knight_hash,
    }
}

fn compile_state(
    source: &'static str,
    fix: &MuxChessFixture,
    white_hash: &[u8],
    black_hash: &[u8],
    board: &[u8],
    turn: i64,
    status: i64,
) -> CompiledContract<'static> {
    let ctor = vec![
        Expr::bytes(fix.mux_hash.clone()),
        Expr::bytes(fix.pawn_hash.clone()),
        Expr::bytes(fix.knight_hash.clone()),
        Expr::bytes(white_hash.to_vec()),
        Expr::bytes(black_hash.to_vec()),
        Expr::bytes(board.to_vec()),
        Expr::int(turn),
        Expr::int(status),
    ];
    compile_contract(source, &ctor, CompileOptions::default()).expect("compile mux chess state")
}

fn entry_sigscript(compiled: &CompiledContract<'_>, function: &str, args: Vec<Expr<'_>>) -> Vec<u8> {
    let sigscript = compiled.build_sig_script(function, args).expect("sigscript builds");
    pay_to_script_hash_signature_script(compiled.script.clone(), sigscript).expect("wrap p2sh sigscript")
}

fn tx_input(index: u32, signature_script: Vec<u8>) -> TransactionInput {
    TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([index as u8 + 1; 32]), index },
        signature_script,
        sequence: 0,
        sig_op_count: 1,
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

fn populate_single_output_genesis_covenant(compiled: &CompiledContract<'_>) -> Hash {
    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x77u8; 32]), index: 0 },
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 0,
    };
    let covenant_id = kaspa_consensus_core::hashing::covenant_id::covenant_id(
        input.previous_outpoint,
        std::iter::once((
            0u32,
            &TransactionOutput { value: 1_000, script_public_key: pay_to_script_hash_script(&compiled.script), covenant: None },
        )),
    );
    let output = TransactionOutput {
        value: 1_000,
        script_public_key: pay_to_script_hash_script(&compiled.script),
        covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id }),
    };
    let tx = Transaction::new(1, vec![input], vec![output], 0, Default::default(), 0, vec![]);
    let populated = PopulatedTransaction::new(&tx, vec![UtxoEntry::new(1_500, Default::default(), 0, false, None)]);
    CovenantsContext::from_tx(&populated).expect("validate genesis covenant bindings");
    covenant_id
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

fn sign_tx_input_schnorr(tx: &Transaction, entries: &[UtxoEntry], input_idx: usize, player: &Player) -> Vec<u8> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let sig_hash = calc_schnorr_signature_hash(&populated, input_idx, SIG_HASH_ALL, &reused_values);
    let msg = Message::from_digest_slice(sig_hash.as_bytes().as_slice()).expect("valid sighash message");
    let sig = player.keypair.sign_schnorr(msg);
    let mut signature = Vec::new();
    signature.extend_from_slice(sig.as_ref());
    signature.push(SIG_HASH_ALL.to_u8());
    signature
}

fn run_route(
    active: &CompiledContract<'_>,
    selector: i64,
    target_prefix: Vec<u8>,
    target_suffix: Vec<u8>,
    out: &CompiledContract<'_>,
    covenant_id: Hash,
) {
    let sigscript = entry_sigscript(active, "route", vec![selector.into(), target_prefix.into(), target_suffix.into()]);
    let input = tx_input(0, sigscript);
    let outputs = vec![covenant_output(out, 0, covenant_id)];
    let entries = vec![covenant_utxo(active, covenant_id)];
    let tx = Transaction::new(1, vec![input], outputs, 0, Default::default(), 0, vec![]);
    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(result.is_ok(), "route should succeed: {:?}", result.unwrap_err());
}

fn run_pawn_apply(
    active: &CompiledContract<'_>,
    next: &CompiledContract<'_>,
    covenant_id: Hash,
    player: &Player,
    from_x: i64,
    from_y: i64,
    to_x: i64,
    to_y: i64,
    mux_prefix: Vec<u8>,
    mux_suffix: Vec<u8>,
) {
    let placeholder_sig = vec![0u8; 65];
    let placeholder_sigscript = entry_sigscript(
        active,
        "apply",
        vec![
            from_x.into(),
            from_y.into(),
            to_x.into(),
            to_y.into(),
            Expr::bytes(placeholder_sig),
            Expr::bytes(player.pubkey_bytes.clone()),
            Expr::bytes(mux_prefix.clone()),
            Expr::bytes(mux_suffix.clone()),
        ],
    );

    let outputs = vec![covenant_output(next, 0, covenant_id)];
    let entries = vec![covenant_utxo(active, covenant_id)];
    let mut signed_tx = Transaction::new(1, vec![tx_input(0, placeholder_sigscript)], outputs, 0, Default::default(), 0, vec![]);
    let sig = sign_tx_input_schnorr(&signed_tx, &entries, 0, player);
    signed_tx.inputs[0].signature_script = entry_sigscript(
        active,
        "apply",
        vec![
            from_x.into(),
            from_y.into(),
            to_x.into(),
            to_y.into(),
            Expr::bytes(sig),
            Expr::bytes(player.pubkey_bytes.clone()),
            Expr::bytes(mux_prefix),
            Expr::bytes(mux_suffix),
        ],
    );

    let result = execute_input_with_covenants(signed_tx, entries, 0);
    assert!(result.is_ok(), "pawn apply should succeed: {:?}", result.unwrap_err());
}

fn run_knight_apply(
    active: &CompiledContract<'_>,
    next: &CompiledContract<'_>,
    covenant_id: Hash,
    player: &Player,
    from_x: i64,
    from_y: i64,
    to_x: i64,
    to_y: i64,
    mux_prefix: Vec<u8>,
    mux_suffix: Vec<u8>,
) {
    let placeholder_sig = vec![0u8; 65];
    let placeholder_sigscript = entry_sigscript(
        active,
        "apply",
        vec![
            from_x.into(),
            from_y.into(),
            to_x.into(),
            to_y.into(),
            Expr::bytes(placeholder_sig),
            Expr::bytes(player.pubkey_bytes.clone()),
            Expr::bytes(mux_prefix.clone()),
            Expr::bytes(mux_suffix.clone()),
        ],
    );

    let outputs = vec![covenant_output(next, 0, covenant_id)];
    let entries = vec![covenant_utxo(active, covenant_id)];
    let mut signed_tx = Transaction::new(1, vec![tx_input(0, placeholder_sigscript)], outputs, 0, Default::default(), 0, vec![]);
    let sig = sign_tx_input_schnorr(&signed_tx, &entries, 0, player);
    signed_tx.inputs[0].signature_script = entry_sigscript(
        active,
        "apply",
        vec![
            from_x.into(),
            from_y.into(),
            to_x.into(),
            to_y.into(),
            Expr::bytes(sig),
            Expr::bytes(player.pubkey_bytes.clone()),
            Expr::bytes(mux_prefix),
            Expr::bytes(mux_suffix),
        ],
    );

    let result = execute_input_with_covenants(signed_tx, entries, 0);
    assert!(result.is_ok(), "knight apply should succeed: {:?}", result.unwrap_err());
}

#[test]
fn muxed_chess_routes_pawn_and_knight_workers() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let board0 = standard_board();
    let mux0 = compile_state(fix.mux_source, &fix, &white.pubkey_hash, &black.pubkey_hash, &board0, 0, 0);
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let pawn0 = compile_state(fix.pawn_source, &fix, &white.pubkey_hash, &black.pubkey_hash, &board0, 0, 0);
    run_route(&mux0, 0, fix.pawn_prefix.clone(), fix.pawn_suffix.clone(), &pawn0, covenant_id);

    let mut board1 = board0.clone();
    move_piece(&mut board1, 4, 1, 4, 3);
    let mux1 = compile_state(fix.mux_source, &fix, &white.pubkey_hash, &black.pubkey_hash, &board1, 1, 0);
    run_pawn_apply(&pawn0, &mux1, covenant_id, &white, 4, 1, 4, 3, fix.mux_prefix.clone(), fix.mux_suffix.clone());

    let knight1 = compile_state(fix.knight_source, &fix, &white.pubkey_hash, &black.pubkey_hash, &board1, 1, 0);
    run_route(&mux1, 1, fix.knight_prefix.clone(), fix.knight_suffix.clone(), &knight1, covenant_id);

    let mut board2 = board1.clone();
    move_piece(&mut board2, 6, 7, 5, 5);
    let mux2 = compile_state(fix.mux_source, &fix, &white.pubkey_hash, &black.pubkey_hash, &board2, 0, 0);
    run_knight_apply(&knight1, &mux2, covenant_id, &black, 6, 7, 5, 5, fix.mux_prefix, fix.mux_suffix);
}
