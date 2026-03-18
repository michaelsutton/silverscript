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

use chess_covenant::{
    castle_challenge_contract_path, castle_contract_path, diag_contract_path, horiz_contract_path, king_contract_path,
    knight_contract_path, mux_contract_path, pawn_contract_path, vert_contract_path,
};

struct Player {
    keypair: Keypair,
    pubkey_bytes: Vec<u8>,
    pubkey_hash: Vec<u8>,
}

struct TemplateFixture {
    source: &'static str,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    hash: Vec<u8>,
}

struct MuxChessFixture {
    mux: TemplateFixture,
    pawn: TemplateFixture,
    knight: TemplateFixture,
    vert: TemplateFixture,
    horiz: TemplateFixture,
    diag: TemplateFixture,
    king: TemplateFixture,
    castle: TemplateFixture,
    castle_challenge: TemplateFixture,
}

struct GameStateArgs<'a> {
    board: &'a [u8],
    turn: i64,
    status: i64,
    castle_rights: [u8; 4],
    en_passant_idx: i64,
    pending_src_idx: i64,
    pending_dst_idx: i64,
    pending_promo: i64,
    recent_castle: i64,
    draw_state: i64,
}

struct MoveArgs {
    from_x: i64,
    from_y: i64,
    to_x: i64,
    to_y: i64,
    promo_piece: i64,
}

fn packed_route_hashes(fix: &MuxChessFixture) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 * 8);
    out.extend_from_slice(&fix.pawn.hash);
    out.extend_from_slice(&fix.knight.hash);
    out.extend_from_slice(&fix.vert.hash);
    out.extend_from_slice(&fix.horiz.hash);
    out.extend_from_slice(&fix.diag.hash);
    out.extend_from_slice(&fix.king.hash);
    out.extend_from_slice(&fix.castle.hash);
    out.extend_from_slice(&fix.castle_challenge.hash);
    out
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

fn template_fixture(source: &'static str, ctor: &[Expr<'_>]) -> TemplateFixture {
    let compiled = compile_contract(source, ctor, CompileOptions::default()).expect("compile template source succeeds");
    let layout = compiled.state_layout;
    let prefix = compiled.script[..layout.start].to_vec();
    let suffix = compiled.script[layout.start + layout.len..].to_vec();
    let hash = Blake2bParams::new().hash_length(32).to_state().update(&prefix).update(&suffix).finalize().as_bytes().to_vec();
    TemplateFixture { source, prefix, suffix, hash }
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

fn move_piece_to(board: &mut [u8], from_x: usize, from_y: usize, to_x: usize, to_y: usize, piece: u8) {
    let from_idx = from_y * 8 + from_x;
    let to_idx = to_y * 8 + to_x;
    board[from_idx] = 0x00;
    board[to_idx] = piece;
}

fn apply_en_passant(
    board: &mut [u8],
    from_x: usize,
    from_y: usize,
    to_x: usize,
    to_y: usize,
    captured_x: usize,
    captured_y: usize,
    piece: u8,
) {
    board[from_y * 8 + from_x] = 0x00;
    board[captured_y * 8 + captured_x] = 0x00;
    board[to_y * 8 + to_x] = piece;
}

fn square_idx(x: i64, y: i64) -> i64 {
    y * 8 + x
}

fn full_castle_rights() -> [u8; 4] {
    [1, 1, 1, 1]
}

fn castle_rights_expr(rights: [u8; 4]) -> Expr<'static> {
    Expr::bytes(rights.to_vec())
}

fn mv(from_x: i64, from_y: i64, to_x: i64, to_y: i64) -> MoveArgs {
    MoveArgs { from_x, from_y, to_x, to_y, promo_piece: 0 }
}

fn mv_promo(from_x: i64, from_y: i64, to_x: i64, to_y: i64, promo_piece: i64) -> MoveArgs {
    MoveArgs { from_x, from_y, to_x, to_y, promo_piece }
}

fn build_fixture() -> MuxChessFixture {
    let mux_source = load_contract_source(mux_contract_path());
    let pawn_source = load_contract_source(pawn_contract_path());
    let knight_source = load_contract_source(knight_contract_path());
    let vert_source = load_contract_source(vert_contract_path());
    let horiz_source = load_contract_source(horiz_contract_path());
    let diag_source = load_contract_source(diag_contract_path());
    let king_source = load_contract_source(king_contract_path());
    let castle_source = load_contract_source(castle_contract_path());
    let castle_challenge_source = load_contract_source(castle_challenge_contract_path());

    let dummy_board = standard_board();
    let ctor = vec![
        Expr::bytes(vec![0x11u8; 32]),
        Expr::bytes(vec![0x33u8; 32 * 8]),
        Expr::bytes(vec![0x21u8; 32]),
        Expr::bytes(vec![0x22u8; 32]),
        Expr::bytes(dummy_board),
        Expr::int(0),
        Expr::int(0),
        castle_rights_expr(full_castle_rights()),
        Expr::int(-1),
        Expr::int(-1),
        Expr::int(-1),
        Expr::int(0),
        Expr::int(0),
        Expr::int(0),
    ];

    MuxChessFixture {
        mux: template_fixture(mux_source, &ctor),
        pawn: template_fixture(pawn_source, &ctor),
        knight: template_fixture(knight_source, &ctor),
        vert: template_fixture(vert_source, &ctor),
        horiz: template_fixture(horiz_source, &ctor),
        diag: template_fixture(diag_source, &ctor),
        king: template_fixture(king_source, &ctor),
        castle: template_fixture(castle_source, &ctor),
        castle_challenge: template_fixture(castle_challenge_source, &ctor),
    }
}

fn compile_state(
    source: &'static str,
    fix: &MuxChessFixture,
    white_hash: &[u8],
    black_hash: &[u8],
    state: GameStateArgs<'_>,
) -> CompiledContract<'static> {
    let ctor = vec![
        Expr::bytes(fix.mux.hash.clone()),
        Expr::bytes(packed_route_hashes(fix)),
        Expr::bytes(white_hash.to_vec()),
        Expr::bytes(black_hash.to_vec()),
        Expr::bytes(state.board.to_vec()),
        Expr::int(state.turn),
        Expr::int(state.status),
        castle_rights_expr(state.castle_rights),
        Expr::int(state.en_passant_idx),
        Expr::int(state.pending_src_idx),
        Expr::int(state.pending_dst_idx),
        Expr::int(state.pending_promo),
        Expr::int(state.recent_castle),
        Expr::int(state.draw_state),
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
    mv: MoveArgs,
    player: &Player,
    target: &TemplateFixture,
    out: &CompiledContract<'_>,
    covenant_id: Hash,
) {
    run_route_with_promo(active, selector, mv, player, target, out, covenant_id);
}

fn run_route_with_promo(
    active: &CompiledContract<'_>,
    selector: i64,
    mv: MoveArgs,
    player: &Player,
    target: &TemplateFixture,
    out: &CompiledContract<'_>,
    covenant_id: Hash,
) {
    let placeholder_sig = vec![0u8; 65];
    let placeholder_sigscript = entry_sigscript(
        active,
        "route",
        vec![
            selector.into(),
            mv.from_x.into(),
            mv.from_y.into(),
            mv.to_x.into(),
            mv.to_y.into(),
            mv.promo_piece.into(),
            Expr::bytes(placeholder_sig),
            Expr::bytes(player.pubkey_bytes.clone()),
            Expr::bytes(target.prefix.clone()),
            Expr::bytes(target.suffix.clone()),
        ],
    );
    let outputs = vec![covenant_output(out, 0, covenant_id)];
    let entries = vec![covenant_utxo(active, covenant_id)];
    let mut tx = Transaction::new(1, vec![tx_input(0, placeholder_sigscript)], outputs, 0, Default::default(), 0, vec![]);
    let sig = sign_tx_input_schnorr(&tx, &entries, 0, player);
    tx.inputs[0].signature_script = entry_sigscript(
        active,
        "route",
        vec![
            selector.into(),
            mv.from_x.into(),
            mv.from_y.into(),
            mv.to_x.into(),
            mv.to_y.into(),
            mv.promo_piece.into(),
            Expr::bytes(sig),
            Expr::bytes(player.pubkey_bytes.clone()),
            Expr::bytes(target.prefix.clone()),
            Expr::bytes(target.suffix.clone()),
        ],
    );
    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(result.is_ok(), "route should succeed: {:?}", result.unwrap_err());
}

fn run_route_err(
    active: &CompiledContract<'_>,
    selector: i64,
    mv: MoveArgs,
    player: &Player,
    target: &TemplateFixture,
    out: &CompiledContract<'_>,
    covenant_id: Hash,
) -> TxScriptError {
    let placeholder_sig = vec![0u8; 65];
    let placeholder_sigscript = entry_sigscript(
        active,
        "route",
        vec![
            selector.into(),
            mv.from_x.into(),
            mv.from_y.into(),
            mv.to_x.into(),
            mv.to_y.into(),
            mv.promo_piece.into(),
            Expr::bytes(placeholder_sig),
            Expr::bytes(player.pubkey_bytes.clone()),
            Expr::bytes(target.prefix.clone()),
            Expr::bytes(target.suffix.clone()),
        ],
    );
    let outputs = vec![covenant_output(out, 0, covenant_id)];
    let entries = vec![covenant_utxo(active, covenant_id)];
    let mut tx = Transaction::new(1, vec![tx_input(0, placeholder_sigscript)], outputs, 0, Default::default(), 0, vec![]);
    let sig = sign_tx_input_schnorr(&tx, &entries, 0, player);
    tx.inputs[0].signature_script = entry_sigscript(
        active,
        "route",
        vec![
            selector.into(),
            mv.from_x.into(),
            mv.from_y.into(),
            mv.to_x.into(),
            mv.to_y.into(),
            mv.promo_piece.into(),
            Expr::bytes(sig),
            Expr::bytes(player.pubkey_bytes.clone()),
            Expr::bytes(target.prefix.clone()),
            Expr::bytes(target.suffix.clone()),
        ],
    );
    execute_input_with_covenants(tx, entries, 0).expect_err("route should fail")
}

fn run_worker_apply(
    label: &str,
    active: &CompiledContract<'_>,
    next: &CompiledContract<'_>,
    covenant_id: Hash,
    mux: &TemplateFixture,
) {
    let sigscript = entry_sigscript(active, "apply", vec![Expr::bytes(mux.prefix.clone()), Expr::bytes(mux.suffix.clone())]);
    let outputs = vec![covenant_output(next, 0, covenant_id)];
    let entries = vec![covenant_utxo(active, covenant_id)];
    let tx = Transaction::new(1, vec![tx_input(0, sigscript)], outputs, 0, Default::default(), 0, vec![]);
    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(result.is_ok(), "{label} worker apply should succeed: {:?}", result.unwrap_err());
}

fn run_worker_timeout(
    label: &str,
    active: &CompiledContract<'_>,
    next: &CompiledContract<'_>,
    covenant_id: Hash,
    mux: &TemplateFixture,
    lock_time: u64,
    sequence: u64,
) {
    let sigscript = entry_sigscript(active, "timeout", vec![Expr::bytes(mux.prefix.clone()), Expr::bytes(mux.suffix.clone())]);
    let outputs = vec![covenant_output(next, 0, covenant_id)];
    let entries = vec![covenant_utxo(active, covenant_id)];
    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([1u8; 32]), index: 0 },
        signature_script: sigscript,
        sequence,
        sig_op_count: 1,
    };
    let tx = Transaction::new(1, vec![input], outputs, lock_time, Default::default(), 0, vec![]);
    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(result.is_ok(), "{label} worker apply should succeed: {:?}", result.unwrap_err());
}

fn run_prep_apply(
    label: &str,
    active: &CompiledContract<'_>,
    next: &CompiledContract<'_>,
    covenant_id: Hash,
    target: &TemplateFixture,
) {
    let sigscript = entry_sigscript(active, "apply", vec![Expr::bytes(target.prefix.clone()), Expr::bytes(target.suffix.clone())]);
    let outputs = vec![covenant_output(next, 0, covenant_id)];
    let entries = vec![covenant_utxo(active, covenant_id)];
    let tx = Transaction::new(1, vec![tx_input(0, sigscript)], outputs, 0, Default::default(), 0, vec![]);
    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(result.is_ok(), "{label} prep apply should succeed: {:?}", result.unwrap_err());
}

fn run_worker_apply_err(
    label: &str,
    active: &CompiledContract<'_>,
    next: &CompiledContract<'_>,
    covenant_id: Hash,
    mux: &TemplateFixture,
) -> TxScriptError {
    let sigscript = entry_sigscript(active, "apply", vec![Expr::bytes(mux.prefix.clone()), Expr::bytes(mux.suffix.clone())]);
    let outputs = vec![covenant_output(next, 0, covenant_id)];
    let entries = vec![covenant_utxo(active, covenant_id)];
    let tx = Transaction::new(1, vec![tx_input(0, sigscript)], outputs, 0, Default::default(), 0, vec![]);
    execute_input_with_covenants(tx, entries, 0).expect_err(label)
}

#[test]
fn muxed_chess_routes_all_move_families() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let board0 = standard_board();
    let mux0 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let pawn0 = compile_state(
        fix.pawn.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(4, 1),
            pending_dst_idx: square_idx(4, 3),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux0, 0, mv(4, 1, 4, 3), &white, &fix.pawn, &pawn0, covenant_id);
    let mut board1 = board0.clone();
    move_piece(&mut board1, 4, 1, 4, 3);
    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: square_idx(4, 2),
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("pawn", &pawn0, &mux1, covenant_id, &fix.mux);

    let knight1 = compile_state(
        fix.knight.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: square_idx(4, 2),
            pending_src_idx: square_idx(6, 7),
            pending_dst_idx: square_idx(5, 5),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux1, 1, mv(6, 7, 5, 5), &black, &fix.knight, &knight1, covenant_id);
    let mut board2 = board1.clone();
    move_piece(&mut board2, 6, 7, 5, 5);
    let mux2 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board2,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("knight", &knight1, &mux2, covenant_id, &fix.mux);

    let mut board3 = vec![0u8; 64];
    board3[0] = 0x04;
    let mux3 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board3,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id3 = populate_single_output_genesis_covenant(&mux3);
    let vert = compile_state(
        fix.vert.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board3,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(0, 0),
            pending_dst_idx: square_idx(0, 3),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux3, 2, mv(0, 0, 0, 3), &white, &fix.vert, &vert, covenant_id3);
    let mut board4 = board3.clone();
    move_piece(&mut board4, 0, 0, 0, 3);
    let mux4 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board4,
            turn: 1,
            status: 0,
            castle_rights: [1, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("vert", &vert, &mux4, covenant_id3, &fix.mux);

    let mut board4q = vec![0u8; 64];
    board4q[0] = 0x05;
    let mux4q = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board4q,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id4q = populate_single_output_genesis_covenant(&mux4q);
    let vert_queen = compile_state(
        fix.vert.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board4q,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(0, 0),
            pending_dst_idx: square_idx(0, 3),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux4q, 2, mv(0, 0, 0, 3), &white, &fix.vert, &vert_queen, covenant_id4q);
    let mut board4q_next = board4q.clone();
    move_piece(&mut board4q_next, 0, 0, 0, 3);
    let mux4q_next = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board4q_next,
            turn: 1,
            status: 0,
            castle_rights: [1, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("vert_queen", &vert_queen, &mux4q_next, covenant_id4q, &fix.mux);

    let mut board5 = vec![0u8; 64];
    board5[56] = 0x0c;
    let mux5 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board5,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id5 = populate_single_output_genesis_covenant(&mux5);
    let vert_black = compile_state(
        fix.vert.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board5,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(0, 7),
            pending_dst_idx: square_idx(0, 4),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux5, 2, mv(0, 7, 0, 4), &black, &fix.vert, &vert_black, covenant_id5);
    let mut board6 = board5.clone();
    move_piece(&mut board6, 0, 7, 0, 4);
    let mux6 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board6,
            turn: 0,
            status: 0,
            castle_rights: [1, 1, 1, 0],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("vert_black", &vert_black, &mux6, covenant_id5, &fix.mux);

    let mut board7 = vec![0u8; 64];
    board7[31] = 0x05;
    let mux7 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board7,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id7 = populate_single_output_genesis_covenant(&mux7);
    let horiz_left = compile_state(
        fix.horiz.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board7,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(7, 3),
            pending_dst_idx: square_idx(4, 3),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux7, 3, mv(7, 3, 4, 3), &white, &fix.horiz, &horiz_left, covenant_id7);
    let mut board8 = board7.clone();
    move_piece(&mut board8, 7, 3, 4, 3);
    let mux8 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board8,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("horiz_left", &horiz_left, &mux8, covenant_id7, &fix.mux);

    let mut board9 = vec![0u8; 64];
    board9[24] = 0x05;
    let mux9 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board9,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id9 = populate_single_output_genesis_covenant(&mux9);
    let horiz_right = compile_state(
        fix.horiz.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board9,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(0, 3),
            pending_dst_idx: square_idx(3, 3),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux9, 3, mv(0, 3, 3, 3), &white, &fix.horiz, &horiz_right, covenant_id9);
    let mut board10 = board9.clone();
    move_piece(&mut board10, 0, 3, 3, 3);
    let mux10 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board10,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("horiz_right", &horiz_right, &mux10, covenant_id9, &fix.mux);

    let mut board11 = vec![0u8; 64];
    board11[0] = 0x03;
    let mux11 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board11,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id11 = populate_single_output_genesis_covenant(&mux11);
    let diag_up_right = compile_state(
        fix.diag.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board11,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(0, 0),
            pending_dst_idx: square_idx(3, 3),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux11, 4, mv(0, 0, 3, 3), &white, &fix.diag, &diag_up_right, covenant_id11);
    let mut board12 = board11.clone();
    move_piece(&mut board12, 0, 0, 3, 3);
    let mux12 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board12,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("diag_up_right", &diag_up_right, &mux12, covenant_id11, &fix.mux);

    let mut board12q = vec![0u8; 64];
    board12q[0] = 0x05;
    let mux12q = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board12q,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id12q = populate_single_output_genesis_covenant(&mux12q);
    let diag_up_right_queen = compile_state(
        fix.diag.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board12q,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(0, 0),
            pending_dst_idx: square_idx(3, 3),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux12q, 4, mv(0, 0, 3, 3), &white, &fix.diag, &diag_up_right_queen, covenant_id12q);
    let mut board12q_next = board12q.clone();
    move_piece(&mut board12q_next, 0, 0, 3, 3);
    let mux12q_next = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board12q_next,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("diag_up_right_queen", &diag_up_right_queen, &mux12q_next, covenant_id12q, &fix.mux);

    let mut board13 = vec![0u8; 64];
    board13[7] = 0x03;
    let mux13 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board13,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id13 = populate_single_output_genesis_covenant(&mux13);
    let diag_up_left = compile_state(
        fix.diag.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board13,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(7, 0),
            pending_dst_idx: square_idx(4, 3),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux13, 4, mv(7, 0, 4, 3), &white, &fix.diag, &diag_up_left, covenant_id13);
    let mut board14 = board13.clone();
    move_piece(&mut board14, 7, 0, 4, 3);
    let mux14 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board14,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("diag_up_left", &diag_up_left, &mux14, covenant_id13, &fix.mux);

    let mut board15 = vec![0u8; 64];
    board15[56] = 0x0b;
    let mux15 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board15,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id15 = populate_single_output_genesis_covenant(&mux15);
    let diag_down_right = compile_state(
        fix.diag.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board15,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(0, 7),
            pending_dst_idx: square_idx(3, 4),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux15, 4, mv(0, 7, 3, 4), &black, &fix.diag, &diag_down_right, covenant_id15);
    let mut board16 = board15.clone();
    move_piece(&mut board16, 0, 7, 3, 4);
    let mux16 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board16,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("diag_down_right", &diag_down_right, &mux16, covenant_id15, &fix.mux);

    let mut board17 = vec![0u8; 64];
    board17[63] = 0x0b;
    let mux17 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board17,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id17 = populate_single_output_genesis_covenant(&mux17);
    let diag_down_left = compile_state(
        fix.diag.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board17,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(7, 7),
            pending_dst_idx: square_idx(4, 4),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux17, 4, mv(7, 7, 4, 4), &black, &fix.diag, &diag_down_left, covenant_id17);
    let mut board18 = board17.clone();
    move_piece(&mut board18, 7, 7, 4, 4);
    let mux18 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board18,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("diag_down_left", &diag_down_left, &mux18, covenant_id17, &fix.mux);

    let mut board19 = vec![0u8; 64];
    board19[4] = 0x06;
    let mux19 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board19,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id19 = populate_single_output_genesis_covenant(&mux19);
    let king = compile_state(
        fix.king.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board19,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(4, 0),
            pending_dst_idx: square_idx(4, 1),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux19, 5, mv(4, 0, 4, 1), &white, &fix.king, &king, covenant_id19);
    let mut board20 = board19.clone();
    move_piece(&mut board20, 4, 0, 4, 1);
    let mux20 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board20,
            turn: 1,
            status: 0,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("king", &king, &mux20, covenant_id19, &fix.mux);

    let mut board21 = vec![0u8; 64];
    board21[4] = 0x06;
    board21[7] = 0x04;
    let mux21 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board21,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id21 = populate_single_output_genesis_covenant(&mux21);
    let castle = compile_state(
        fix.castle.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board21,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(4, 0),
            pending_dst_idx: square_idx(6, 0),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux21, 6, mv(4, 0, 6, 0), &white, &fix.castle, &castle, covenant_id21);
    let mut board22 = board21.clone();
    board22[4] = 0x00;
    board22[5] = 0x04;
    board22[6] = 0x06;
    board22[7] = 0x00;
    let mux22 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board22,
            turn: 1,
            status: 0,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 1,
            draw_state: 0,
        },
    );
    run_worker_apply("castle", &castle, &mux22, covenant_id21, &fix.mux);
}

#[test]
fn capturing_enemy_king_sets_terminal_status() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let mut board0 = vec![0u8; 64];
    board0[0] = 0x05;
    board0[24] = 0x0e;

    let mux0 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let vert = compile_state(
        fix.vert.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(0, 0),
            pending_dst_idx: square_idx(0, 3),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux0, 2, mv(0, 0, 0, 3), &white, &fix.vert, &vert, covenant_id);

    let mut board1 = board0.clone();
    move_piece(&mut board1, 0, 0, 0, 3);
    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 1,
            status: 1,
            castle_rights: [1, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("vert_king_capture", &vert, &mux1, covenant_id, &fix.mux);
}

#[test]
fn pawn_underpromotion_to_knight_succeeds() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let mut board0 = vec![0u8; 64];
    board0[square_idx(4, 6) as usize] = 0x01;

    let mux0 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let pawn0 = compile_state(
        fix.pawn.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(4, 6),
            pending_dst_idx: square_idx(4, 7),
            pending_promo: 2,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route_with_promo(&mux0, 0, mv_promo(4, 6, 4, 7, 2), &white, &fix.pawn, &pawn0, covenant_id);

    let mut board1 = board0.clone();
    move_piece_to(&mut board1, 4, 6, 4, 7, 0x02);
    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("pawn_underpromotion", &pawn0, &mux1, covenant_id, &fix.mux);
}

#[test]
fn pawn_promotion_requires_choice() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let mut board0 = vec![0u8; 64];
    board0[square_idx(4, 6) as usize] = 0x01;

    let mux0 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let pawn0 = compile_state(
        fix.pawn.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(4, 6),
            pending_dst_idx: square_idx(4, 7),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux0, 0, mv(4, 6, 4, 7), &white, &fix.pawn, &pawn0, covenant_id);

    let mut board1 = board0.clone();
    move_piece_to(&mut board1, 4, 6, 4, 7, 0x01);
    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let _err = run_worker_apply_err("missing promotion choice should fail", &pawn0, &mux1, covenant_id, &fix.mux);
}

#[test]
fn non_promotion_pawn_move_rejects_promotion_choice() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let mut board0 = vec![0u8; 64];
    board0[square_idx(4, 1) as usize] = 0x01;

    let mux0 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let pawn0 = compile_state(
        fix.pawn.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(4, 1),
            pending_dst_idx: square_idx(4, 2),
            pending_promo: 5,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route_with_promo(&mux0, 0, mv_promo(4, 1, 4, 2, 5), &white, &fix.pawn, &pawn0, covenant_id);

    let mut board1 = board0.clone();
    move_piece_to(&mut board1, 4, 1, 4, 2, 0x01);
    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let _err = run_worker_apply_err("ordinary pawn move with promotion choice should fail", &pawn0, &mux1, covenant_id, &fix.mux);
}

#[test]
fn white_en_passant_capture_succeeds() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let mut board0 = vec![0u8; 64];
    board0[square_idx(4, 4) as usize] = 0x01;
    board0[square_idx(3, 4) as usize] = 0x09;

    let mux0 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: square_idx(3, 5),
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let pawn0 = compile_state(
        fix.pawn.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: square_idx(3, 5),
            pending_src_idx: square_idx(4, 4),
            pending_dst_idx: square_idx(3, 5),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux0, 0, mv(4, 4, 3, 5), &white, &fix.pawn, &pawn0, covenant_id);

    let mut board1 = board0.clone();
    apply_en_passant(&mut board1, 4, 4, 3, 5, 3, 4, 0x01);
    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("white_en_passant", &pawn0, &mux1, covenant_id, &fix.mux);
}

#[test]
fn black_en_passant_capture_succeeds() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let mut board0 = vec![0u8; 64];
    board0[square_idx(3, 3) as usize] = 0x09;
    board0[square_idx(4, 3) as usize] = 0x01;

    let mux0 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: square_idx(4, 2),
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let pawn0 = compile_state(
        fix.pawn.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: square_idx(4, 2),
            pending_src_idx: square_idx(3, 3),
            pending_dst_idx: square_idx(4, 2),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux0, 0, mv(3, 3, 4, 2), &black, &fix.pawn, &pawn0, covenant_id);

    let mut board1 = board0.clone();
    apply_en_passant(&mut board1, 3, 3, 4, 2, 4, 3, 0x09);
    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("black_en_passant", &pawn0, &mux1, covenant_id, &fix.mux);
}

#[test]
fn non_pawn_move_clears_en_passant_state() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let mut board0 = vec![0u8; 64];
    board0[square_idx(1, 0) as usize] = 0x02;

    let mux0 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: square_idx(3, 5),
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let knight0 = compile_state(
        fix.knight.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: square_idx(3, 5),
            pending_src_idx: square_idx(1, 0),
            pending_dst_idx: square_idx(2, 2),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux0, 1, mv(1, 0, 2, 2), &white, &fix.knight, &knight0, covenant_id);

    let mut board1 = board0.clone();
    move_piece(&mut board1, 1, 0, 2, 2);
    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("knight_clears_en_passant", &knight0, &mux1, covenant_id, &fix.mux);
}

#[test]
fn pawn_diagonal_capture_succeeds() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let mut board0 = vec![0u8; 64];
    board0[square_idx(4, 4) as usize] = 0x01;
    board0[square_idx(5, 5) as usize] = 0x0a;

    let mux0 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let pawn0 = compile_state(
        fix.pawn.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(4, 4),
            pending_dst_idx: square_idx(5, 5),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux0, 0, mv(4, 4, 5, 5), &white, &fix.pawn, &pawn0, covenant_id);

    let mut board1 = board0.clone();
    move_piece(&mut board1, 4, 4, 5, 5);
    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("pawn_diagonal_capture", &pawn0, &mux1, covenant_id, &fix.mux);
}

#[test]
fn pawn_double_step_blocked_by_occupied_middle_square_fails() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let mut board0 = vec![0u8; 64];
    board0[square_idx(4, 1) as usize] = 0x01;
    board0[square_idx(4, 2) as usize] = 0x09;

    let mux0 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let pawn0 = compile_state(
        fix.pawn.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(4, 1),
            pending_dst_idx: square_idx(4, 3),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux0, 0, mv(4, 1, 4, 3), &white, &fix.pawn, &pawn0, covenant_id);

    let mut board1 = board0.clone();
    move_piece(&mut board1, 4, 1, 4, 3);
    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: square_idx(4, 2),
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let _err = run_worker_apply_err("blocked double-step should fail", &pawn0, &mux1, covenant_id, &fix.mux);
}

#[test]
fn pawn_diagonal_move_into_empty_square_fails_without_en_passant() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let mut board0 = vec![0u8; 64];
    board0[square_idx(4, 4) as usize] = 0x01;

    let mux0 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let pawn0 = compile_state(
        fix.pawn.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(4, 4),
            pending_dst_idx: square_idx(5, 5),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux0, 0, mv(4, 4, 5, 5), &white, &fix.pawn, &pawn0, covenant_id);

    let mut board1 = board0.clone();
    move_piece(&mut board1, 4, 4, 5, 5);
    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let _err = run_worker_apply_err("diagonal move into empty square should fail", &pawn0, &mux1, covenant_id, &fix.mux);
}

#[test]
fn expired_en_passant_attempt_fails() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let mut board0 = vec![0u8; 64];
    board0[square_idx(4, 4) as usize] = 0x01;
    board0[square_idx(3, 4) as usize] = 0x09;

    let mux0 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let pawn0 = compile_state(
        fix.pawn.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(4, 4),
            pending_dst_idx: square_idx(3, 5),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux0, 0, mv(4, 4, 3, 5), &white, &fix.pawn, &pawn0, covenant_id);

    let mut board1 = board0.clone();
    apply_en_passant(&mut board1, 4, 4, 3, 5, 3, 4, 0x01);
    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let _err = run_worker_apply_err("expired en-passant should fail", &pawn0, &mux1, covenant_id, &fix.mux);
}

#[test]
fn ordinary_reply_after_castle_clears_recent_castle() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let mut board0 = vec![0u8; 64];
    board0[5] = 0x04;
    board0[6] = 0x06;
    board0[62] = 0x0a;

    let mux0 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 1,
            draw_state: 0,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let knight0 = compile_state(
        fix.knight.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: square_idx(6, 7),
            pending_dst_idx: square_idx(5, 5),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux0, 1, mv(6, 7, 5, 5), &black, &fix.knight, &knight0, covenant_id);

    let mut board1 = board0.clone();
    move_piece(&mut board1, 6, 7, 5, 5);
    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 0,
            status: 0,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("ordinary_reply_clears_recent_castle", &knight0, &mux1, covenant_id, &fix.mux);
}

#[test]
fn castle_start_square_challenge_by_pawn_succeeds() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let mut board0 = vec![0u8; 64];
    board0[5] = 0x04;
    board0[6] = 0x06;
    board0[11] = 0x09;

    let mux0 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 1,
            draw_state: 0,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let prep0 = compile_state(
        fix.castle_challenge.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: square_idx(3, 1),
            pending_dst_idx: square_idx(4, 0),
            pending_promo: 0,
            recent_castle: 1,
            draw_state: 0,
        },
    );
    run_route(&mux0, 7, mv(3, 1, 4, 0), &black, &fix.castle_challenge, &prep0, covenant_id);

    let mut proof_board = vec![0u8; 64];
    proof_board[4] = 0x06;
    proof_board[7] = 0x04;
    proof_board[11] = 0x09;
    let pawn0 = compile_state(
        fix.pawn.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &proof_board,
            turn: 1,
            status: 0,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: square_idx(3, 1),
            pending_dst_idx: square_idx(4, 0),
            pending_promo: 0,
            recent_castle: 1,
            draw_state: 0,
        },
    );
    run_prep_apply("castle_start_square_prep", &prep0, &pawn0, covenant_id, &fix.pawn);

    let mut board1 = proof_board.clone();
    move_piece(&mut board1, 3, 1, 4, 0);
    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 0,
            status: 2,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("castle_start_square_pawn_challenge", &pawn0, &mux1, covenant_id, &fix.mux);
}

#[test]
fn castle_transit_square_challenge_by_rook_succeeds() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let mut board0 = vec![0u8; 64];
    board0[5] = 0x04;
    board0[6] = 0x06;
    board0[61] = 0x0c;

    let mux0 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 1,
            draw_state: 0,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let prep0 = compile_state(
        fix.castle_challenge.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: square_idx(5, 7),
            pending_dst_idx: square_idx(5, 0),
            pending_promo: 0,
            recent_castle: 1,
            draw_state: 0,
        },
    );
    run_route(&mux0, 7, mv(5, 7, 5, 0), &black, &fix.castle_challenge, &prep0, covenant_id);

    let mut proof_board = vec![0u8; 64];
    proof_board[5] = 0x06;
    proof_board[7] = 0x04;
    proof_board[61] = 0x0c;
    let vert0 = compile_state(
        fix.vert.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &proof_board,
            turn: 1,
            status: 0,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: square_idx(5, 7),
            pending_dst_idx: square_idx(5, 0),
            pending_promo: 0,
            recent_castle: 1,
            draw_state: 0,
        },
    );
    run_prep_apply("castle_transit_square_prep", &prep0, &vert0, covenant_id, &fix.vert);

    let mut board1 = proof_board.clone();
    move_piece(&mut board1, 5, 7, 5, 0);
    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 0,
            status: 2,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("castle_transit_square_rook_challenge", &vert0, &mux1, covenant_id, &fix.mux);
}

#[test]
fn castle_destination_square_challenge_by_rook_succeeds() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let mut board0 = vec![0u8; 64];
    board0[5] = 0x04;
    board0[6] = 0x06;
    board0[62] = 0x0c;

    let mux0 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 1,
            draw_state: 0,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let prep0 = compile_state(
        fix.castle_challenge.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: square_idx(6, 7),
            pending_dst_idx: square_idx(6, 0),
            pending_promo: 0,
            recent_castle: 1,
            draw_state: 0,
        },
    );
    run_route(&mux0, 7, mv(6, 7, 6, 0), &black, &fix.castle_challenge, &prep0, covenant_id);

    let vert0 = compile_state(
        fix.vert.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: square_idx(6, 7),
            pending_dst_idx: square_idx(6, 0),
            pending_promo: 0,
            recent_castle: 1,
            draw_state: 0,
        },
    );
    run_prep_apply("castle_destination_square_prep", &prep0, &vert0, covenant_id, &fix.vert);

    let mut board1 = board0.clone();
    move_piece(&mut board1, 6, 7, 6, 0);
    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 0,
            status: 2,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("castle_destination_square_rook_challenge", &vert0, &mux1, covenant_id, &fix.mux);
}

#[test]
fn white_queenside_castle_destination_challenge_succeeds() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let mut board0 = vec![0u8; 64];
    board0[2] = 0x06;
    board0[3] = 0x04;
    board0[58] = 0x0c;

    let mux0 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 2,
            draw_state: 0,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let prep0 = compile_state(
        fix.castle_challenge.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: square_idx(2, 7),
            pending_dst_idx: square_idx(2, 0),
            pending_promo: 0,
            recent_castle: 2,
            draw_state: 0,
        },
    );
    run_route(&mux0, 7, mv(2, 7, 2, 0), &black, &fix.castle_challenge, &prep0, covenant_id);

    let vert0 = compile_state(
        fix.vert.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: square_idx(2, 7),
            pending_dst_idx: square_idx(2, 0),
            pending_promo: 0,
            recent_castle: 2,
            draw_state: 0,
        },
    );
    run_prep_apply("white_queenside_destination_prep", &prep0, &vert0, covenant_id, &fix.vert);

    let mut board1 = board0.clone();
    move_piece(&mut board1, 2, 7, 2, 0);
    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 0,
            status: 2,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("white_queenside_destination_challenge", &vert0, &mux1, covenant_id, &fix.mux);
}

#[test]
fn black_kingside_castle_start_challenge_by_pawn_succeeds() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let mut board0 = vec![0u8; 64];
    board0[61] = 0x0c;
    board0[62] = 0x0e;
    board0[51] = 0x01;

    let mux0 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: [1, 1, 0, 0],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 3,
            draw_state: 0,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let prep0 = compile_state(
        fix.castle_challenge.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: [1, 1, 0, 0],
            en_passant_idx: -1,
            pending_src_idx: square_idx(3, 6),
            pending_dst_idx: square_idx(4, 7),
            pending_promo: 0,
            recent_castle: 3,
            draw_state: 0,
        },
    );
    run_route(&mux0, 7, mv(3, 6, 4, 7), &white, &fix.castle_challenge, &prep0, covenant_id);

    let mut proof_board = vec![0u8; 64];
    proof_board[60] = 0x0e;
    proof_board[63] = 0x0c;
    proof_board[51] = 0x01;
    let pawn0 = compile_state(
        fix.pawn.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &proof_board,
            turn: 0,
            status: 0,
            castle_rights: [1, 1, 0, 0],
            en_passant_idx: -1,
            pending_src_idx: square_idx(3, 6),
            pending_dst_idx: square_idx(4, 7),
            pending_promo: 0,
            recent_castle: 3,
            draw_state: 0,
        },
    );
    run_prep_apply("black_kingside_start_prep", &prep0, &pawn0, covenant_id, &fix.pawn);

    let mut board1 = proof_board.clone();
    move_piece(&mut board1, 3, 6, 4, 7);
    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 1,
            status: 1,
            castle_rights: [1, 1, 0, 0],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("black_kingside_start_challenge", &pawn0, &mux1, covenant_id, &fix.mux);
}

#[test]
fn black_queenside_castle_transit_challenge_by_rook_succeeds() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let mut board0 = vec![0u8; 64];
    board0[58] = 0x0e;
    board0[59] = 0x0c;
    board0[3] = 0x04;

    let mux0 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: [1, 1, 0, 0],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 4,
            draw_state: 0,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let prep0 = compile_state(
        fix.castle_challenge.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: [1, 1, 0, 0],
            en_passant_idx: -1,
            pending_src_idx: square_idx(3, 0),
            pending_dst_idx: square_idx(3, 7),
            pending_promo: 0,
            recent_castle: 4,
            draw_state: 0,
        },
    );
    run_route(&mux0, 7, mv(3, 0, 3, 7), &white, &fix.castle_challenge, &prep0, covenant_id);

    let mut proof_board = vec![0u8; 64];
    proof_board[56] = 0x0c;
    proof_board[59] = 0x0e;
    proof_board[3] = 0x04;
    let vert0 = compile_state(
        fix.vert.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &proof_board,
            turn: 0,
            status: 0,
            castle_rights: [1, 1, 0, 0],
            en_passant_idx: -1,
            pending_src_idx: square_idx(3, 0),
            pending_dst_idx: square_idx(3, 7),
            pending_promo: 0,
            recent_castle: 4,
            draw_state: 0,
        },
    );
    run_prep_apply("black_queenside_transit_prep", &prep0, &vert0, covenant_id, &fix.vert);

    let mut board1 = proof_board.clone();
    move_piece(&mut board1, 3, 0, 3, 7);
    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 1,
            status: 1,
            castle_rights: [1, 1, 0, 0],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_worker_apply("black_queenside_transit_challenge", &vert0, &mux1, covenant_id, &fix.mux);
}

#[test]
fn claim_draw_flips_turn_and_enters_draw_state() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let board0 = standard_board();
    let mux0 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 1,
        },
    );
    run_route(&mux0, 8, mv(0, 0, 0, 0), &white, &fix.mux, &mux1, covenant_id);
}

#[test]
fn surrender_routes_back_to_mux_with_terminal_status() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let board0 = standard_board();
    let mux0 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: square_idx(4, 2),
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 1,
            draw_state: 1,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 2,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    run_route(&mux0, 9, mv(0, 0, 0, 0), &white, &fix.mux, &mux1, covenant_id);
}

#[test]
fn knight_draw_negotiation_flips_side_control_and_false_claim_loses() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let mut board0 = vec![0u8; 64];
    board0[square_idx(1, 0) as usize] = 0x02;
    board0[square_idx(6, 7) as usize] = 0x0a;

    let mux0 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 1,
        },
    );
    run_route(&mux0, 8, mv(0, 0, 0, 0), &white, &fix.mux, &mux1, covenant_id);

    let knight1 = compile_state(
        fix.knight.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(1, 0),
            pending_dst_idx: square_idx(2, 2),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 1,
        },
    );
    run_route(&mux1, 1, mv(1, 0, 2, 2), &black, &fix.knight, &knight1, covenant_id);

    let mut board1 = board0.clone();
    move_piece(&mut board1, 1, 0, 2, 2);
    let mux2 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 2,
        },
    );
    run_worker_apply("draw_knight_refute", &knight1, &mux2, covenant_id, &fix.mux);

    let knight2 = compile_state(
        fix.knight.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(6, 7),
            pending_dst_idx: square_idx(5, 5),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 2,
        },
    );
    run_route(&mux2, 1, mv(6, 7, 5, 5), &white, &fix.knight, &knight2, covenant_id);

    let mut board2 = board1.clone();
    move_piece(&mut board2, 6, 7, 5, 5);
    let mux3 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board2,
            turn: 1,
            status: 2,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 2,
        },
    );
    run_worker_apply("draw_knight_counter", &knight2, &mux3, covenant_id, &fix.mux);
}

#[test]
fn knight_draw_capture_awards_win_to_the_actor() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let mut board0 = vec![0u8; 64];
    board0[square_idx(1, 0) as usize] = 0x02;
    board0[square_idx(2, 2) as usize] = 0x0e;

    let mux0 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 1,
        },
    );
    run_route(&mux0, 8, mv(0, 0, 0, 0), &white, &fix.mux, &mux1, covenant_id);

    let knight1 = compile_state(
        fix.knight.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(1, 0),
            pending_dst_idx: square_idx(2, 2),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 1,
        },
    );
    run_route(&mux1, 1, mv(1, 0, 2, 2), &black, &fix.knight, &knight1, covenant_id);

    let mut board1 = board0.clone();
    move_piece(&mut board1, 1, 0, 2, 2);
    let mux2 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 0,
            status: 2,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 2,
        },
    );
    run_worker_apply("draw_knight_capture_black_actor_wins", &knight1, &mux2, covenant_id, &fix.mux);
}

#[test]
fn pawn_draw_capture_awards_win_to_the_actor() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let mut board0 = vec![0u8; 64];
    board0[square_idx(3, 3) as usize] = 0x01;
    board0[square_idx(4, 4) as usize] = 0x0e;

    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 1,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux1);

    let pawn1 = compile_state(
        fix.pawn.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(3, 3),
            pending_dst_idx: square_idx(4, 4),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 1,
        },
    );
    run_route(&mux1, 0, mv(3, 3, 4, 4), &black, &fix.pawn, &pawn1, covenant_id);

    let mut board1 = board0.clone();
    move_piece(&mut board1, 3, 3, 4, 4);
    let mux2 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 0,
            status: 2,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 2,
        },
    );
    run_worker_apply("draw_pawn_capture_black_actor_wins", &pawn1, &mux2, covenant_id, &fix.mux);
}

#[test]
fn draw_mode_reuses_ordinary_workers() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    // pawn
    let mut board0 = vec![0u8; 64];
    board0[square_idx(4, 1) as usize] = 0x01;
    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 1,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux1);
    let pawn1 = compile_state(
        fix.pawn.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(4, 1),
            pending_dst_idx: square_idx(4, 2),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 1,
        },
    );
    run_route(&mux1, 0, mv(4, 1, 4, 2), &black, &fix.pawn, &pawn1, covenant_id);
    let mut board1 = board0.clone();
    move_piece(&mut board1, 4, 1, 4, 2);
    let mux2 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 2,
        },
    );
    run_worker_apply("draw_pawn_refute", &pawn1, &mux2, covenant_id, &fix.mux);

    // vert
    let mut board0 = vec![0u8; 64];
    board0[square_idx(0, 0) as usize] = 0x04;
    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 1,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux1);
    let vert1 = compile_state(
        fix.vert.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(0, 0),
            pending_dst_idx: square_idx(0, 3),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 1,
        },
    );
    run_route(&mux1, 2, mv(0, 0, 0, 3), &black, &fix.vert, &vert1, covenant_id);
    let mut board1 = board0.clone();
    move_piece(&mut board1, 0, 0, 0, 3);
    let mux2 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 0,
            status: 0,
            castle_rights: [1, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 2,
        },
    );
    run_worker_apply("draw_vert_refute", &vert1, &mux2, covenant_id, &fix.mux);

    // horiz
    let mut board0 = vec![0u8; 64];
    board0[square_idx(0, 0) as usize] = 0x04;
    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 1,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux1);
    let horiz1 = compile_state(
        fix.horiz.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(0, 0),
            pending_dst_idx: square_idx(3, 0),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 1,
        },
    );
    run_route(&mux1, 3, mv(0, 0, 3, 0), &black, &fix.horiz, &horiz1, covenant_id);
    let mut board1 = board0.clone();
    move_piece(&mut board1, 0, 0, 3, 0);
    let mux2 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 0,
            status: 0,
            castle_rights: [1, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 2,
        },
    );
    run_worker_apply("draw_horiz_refute", &horiz1, &mux2, covenant_id, &fix.mux);

    // diag
    let mut board0 = vec![0u8; 64];
    board0[square_idx(2, 0) as usize] = 0x03;
    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 1,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux1);
    let diag1 = compile_state(
        fix.diag.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(2, 0),
            pending_dst_idx: square_idx(5, 3),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 1,
        },
    );
    run_route(&mux1, 4, mv(2, 0, 5, 3), &black, &fix.diag, &diag1, covenant_id);
    let mut board1 = board0.clone();
    move_piece(&mut board1, 2, 0, 5, 3);
    let mux2 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 2,
        },
    );
    run_worker_apply("draw_diag_refute", &diag1, &mux2, covenant_id, &fix.mux);

    // king
    let mut board0 = vec![0u8; 64];
    board0[square_idx(4, 0) as usize] = 0x06;
    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 1,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux1);
    let king1 = compile_state(
        fix.king.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(4, 0),
            pending_dst_idx: square_idx(4, 1),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 1,
        },
    );
    run_route(&mux1, 5, mv(4, 0, 4, 1), &black, &fix.king, &king1, covenant_id);
    let mut board1 = board0.clone();
    move_piece(&mut board1, 4, 0, 4, 1);
    let mux2 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board1,
            turn: 0,
            status: 0,
            castle_rights: [0, 0, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 2,
        },
    );
    run_worker_apply("draw_king_refute", &king1, &mux2, covenant_id, &fix.mux);
}

#[test]
fn draw_mode_disallows_castle_and_castle_challenge_routes() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let mut board = vec![0u8; 64];
    board[square_idx(4, 0) as usize] = 0x06;
    board[square_idx(7, 0) as usize] = 0x04;

    let mux1 = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 1,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux1);
    let castle1 = compile_state(
        fix.castle.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(4, 0),
            pending_dst_idx: square_idx(6, 0),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 1,
        },
    );
    let _err = run_route_err(&mux1, 6, mv(4, 0, 6, 0), &black, &fix.castle, &castle1, covenant_id);

    let prep1 = compile_state(
        fix.castle_challenge.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board,
            turn: 1,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(4, 0),
            pending_dst_idx: square_idx(6, 0),
            pending_promo: 0,
            recent_castle: 1,
            draw_state: 1,
        },
    );
    let _err = run_route_err(&mux1, 7, mv(4, 0, 6, 0), &black, &fix.castle_challenge, &prep1, covenant_id);
}

#[test]
fn knight_worker_timeout_rescues_invalid_committed_state() {
    let fix = build_fixture();
    let white = player_from_seed(1);
    let black = player_from_seed(2);

    let board0 = standard_board();
    let knight1 = compile_state(
        fix.knight.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 0,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: square_idx(0, 1),
            pending_dst_idx: square_idx(0, 2),
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&knight1);
    let mux_terminal = compile_state(
        fix.mux.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs {
            board: &board0,
            turn: 0,
            status: 2,
            castle_rights: full_castle_rights(),
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 0,
        },
    );

    run_worker_timeout("knight_timeout", &knight1, &mux_terminal, covenant_id, &fix.mux, 599, 0);
}
