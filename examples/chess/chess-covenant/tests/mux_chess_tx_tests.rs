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
    diag_down_left_contract_path, diag_down_right_contract_path, diag_up_left_contract_path, diag_up_right_contract_path,
    horiz_left_contract_path, horiz_right_contract_path, king_contract_path, knight_contract_path, mux_contract_path,
    pawn_contract_path, vert_down_contract_path, vert_up_contract_path,
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
    vert_up: TemplateFixture,
    vert_down: TemplateFixture,
    horiz_left: TemplateFixture,
    horiz_right: TemplateFixture,
    diag_up_right: TemplateFixture,
    diag_up_left: TemplateFixture,
    diag_down_right: TemplateFixture,
    diag_down_left: TemplateFixture,
    king: TemplateFixture,
}

struct GameStateArgs<'a> {
    board: &'a [u8],
    turn: i64,
    status: i64,
    pending_from_x: i64,
    pending_from_y: i64,
    pending_to_x: i64,
    pending_to_y: i64,
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

fn build_fixture() -> MuxChessFixture {
    let mux_source = load_contract_source(mux_contract_path());
    let pawn_source = load_contract_source(pawn_contract_path());
    let knight_source = load_contract_source(knight_contract_path());
    let file_up_source = load_contract_source(vert_up_contract_path());
    let file_down_source = load_contract_source(vert_down_contract_path());
    let rank_left_source = load_contract_source(horiz_left_contract_path());
    let rank_right_source = load_contract_source(horiz_right_contract_path());
    let diag_up_right_source = load_contract_source(diag_up_right_contract_path());
    let diag_up_left_source = load_contract_source(diag_up_left_contract_path());
    let diag_down_right_source = load_contract_source(diag_down_right_contract_path());
    let diag_down_left_source = load_contract_source(diag_down_left_contract_path());
    let king_source = load_contract_source(king_contract_path());

    let dummy_board = standard_board();
    let ctor = vec![
        Expr::bytes(vec![0x11u8; 32]),
        Expr::bytes(vec![0x12u8; 32]),
        Expr::bytes(vec![0x13u8; 32]),
        Expr::bytes(vec![0x14u8; 32]),
        Expr::bytes(vec![0x15u8; 32]),
        Expr::bytes(vec![0x16u8; 32]),
        Expr::bytes(vec![0x17u8; 32]),
        Expr::bytes(vec![0x18u8; 32]),
        Expr::bytes(vec![0x19u8; 32]),
        Expr::bytes(vec![0x1au8; 32]),
        Expr::bytes(vec![0x1bu8; 32]),
        Expr::bytes(vec![0x1cu8; 32]),
        Expr::bytes(vec![0x21u8; 32]),
        Expr::bytes(vec![0x22u8; 32]),
        Expr::bytes(dummy_board),
        Expr::int(0),
        Expr::int(0),
        Expr::int(-1),
        Expr::int(-1),
        Expr::int(-1),
        Expr::int(-1),
    ];

    MuxChessFixture {
        mux: template_fixture(mux_source, &ctor),
        pawn: template_fixture(pawn_source, &ctor),
        knight: template_fixture(knight_source, &ctor),
        vert_up: template_fixture(file_up_source, &ctor),
        vert_down: template_fixture(file_down_source, &ctor),
        horiz_left: template_fixture(rank_left_source, &ctor),
        horiz_right: template_fixture(rank_right_source, &ctor),
        diag_up_right: template_fixture(diag_up_right_source, &ctor),
        diag_up_left: template_fixture(diag_up_left_source, &ctor),
        diag_down_right: template_fixture(diag_down_right_source, &ctor),
        diag_down_left: template_fixture(diag_down_left_source, &ctor),
        king: template_fixture(king_source, &ctor),
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
        Expr::bytes(fix.pawn.hash.clone()),
        Expr::bytes(fix.knight.hash.clone()),
        Expr::bytes(fix.vert_up.hash.clone()),
        Expr::bytes(fix.vert_down.hash.clone()),
        Expr::bytes(fix.horiz_left.hash.clone()),
        Expr::bytes(fix.horiz_right.hash.clone()),
        Expr::bytes(fix.diag_up_right.hash.clone()),
        Expr::bytes(fix.diag_up_left.hash.clone()),
        Expr::bytes(fix.diag_down_right.hash.clone()),
        Expr::bytes(fix.diag_down_left.hash.clone()),
        Expr::bytes(fix.king.hash.clone()),
        Expr::bytes(white_hash.to_vec()),
        Expr::bytes(black_hash.to_vec()),
        Expr::bytes(state.board.to_vec()),
        Expr::int(state.turn),
        Expr::int(state.status),
        Expr::int(state.pending_from_x),
        Expr::int(state.pending_from_y),
        Expr::int(state.pending_to_x),
        Expr::int(state.pending_to_y),
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
    from_x: i64,
    from_y: i64,
    to_x: i64,
    to_y: i64,
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
            from_x.into(),
            from_y.into(),
            to_x.into(),
            to_y.into(),
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
            from_x.into(),
            from_y.into(),
            to_x.into(),
            to_y.into(),
            Expr::bytes(sig),
            Expr::bytes(player.pubkey_bytes.clone()),
            Expr::bytes(target.prefix.clone()),
            Expr::bytes(target.suffix.clone()),
        ],
    );
    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(result.is_ok(), "route should succeed: {:?}", result.unwrap_err());
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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
        },
    );
    let covenant_id = populate_single_output_genesis_covenant(&mux0);

    let pawn0 = compile_state(
        fix.pawn.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs { board: &board0, turn: 0, status: 0, pending_from_x: 4, pending_from_y: 1, pending_to_x: 4, pending_to_y: 3 },
    );
    run_route(&mux0, 0, 4, 1, 4, 3, &white, &fix.pawn, &pawn0, covenant_id);
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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
        },
    );
    run_worker_apply("pawn", &pawn0, &mux1, covenant_id, &fix.mux);

    let knight1 = compile_state(
        fix.knight.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs { board: &board1, turn: 1, status: 0, pending_from_x: 6, pending_from_y: 7, pending_to_x: 5, pending_to_y: 5 },
    );
    run_route(&mux1, 1, 6, 7, 5, 5, &black, &fix.knight, &knight1, covenant_id);
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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
        },
    );
    let covenant_id3 = populate_single_output_genesis_covenant(&mux3);
    let vert_up = compile_state(
        fix.vert_up.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs { board: &board3, turn: 0, status: 0, pending_from_x: 0, pending_from_y: 0, pending_to_x: 0, pending_to_y: 3 },
    );
    run_route(&mux3, 2, 0, 0, 0, 3, &white, &fix.vert_up, &vert_up, covenant_id3);
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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
        },
    );
    run_worker_apply("vert_up", &vert_up, &mux4, covenant_id3, &fix.mux);

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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
        },
    );
    let covenant_id4q = populate_single_output_genesis_covenant(&mux4q);
    let vert_up_queen = compile_state(
        fix.vert_up.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs { board: &board4q, turn: 0, status: 0, pending_from_x: 0, pending_from_y: 0, pending_to_x: 0, pending_to_y: 3 },
    );
    run_route(&mux4q, 2, 0, 0, 0, 3, &white, &fix.vert_up, &vert_up_queen, covenant_id4q);
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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
        },
    );
    run_worker_apply("vert_up_queen", &vert_up_queen, &mux4q_next, covenant_id4q, &fix.mux);

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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
        },
    );
    let covenant_id5 = populate_single_output_genesis_covenant(&mux5);
    let vert_down = compile_state(
        fix.vert_down.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs { board: &board5, turn: 1, status: 0, pending_from_x: 0, pending_from_y: 7, pending_to_x: 0, pending_to_y: 4 },
    );
    run_route(&mux5, 3, 0, 7, 0, 4, &black, &fix.vert_down, &vert_down, covenant_id5);
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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
        },
    );
    run_worker_apply("vert_down", &vert_down, &mux6, covenant_id5, &fix.mux);

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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
        },
    );
    let covenant_id7 = populate_single_output_genesis_covenant(&mux7);
    let horiz_left = compile_state(
        fix.horiz_left.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs { board: &board7, turn: 0, status: 0, pending_from_x: 7, pending_from_y: 3, pending_to_x: 4, pending_to_y: 3 },
    );
    run_route(&mux7, 4, 7, 3, 4, 3, &white, &fix.horiz_left, &horiz_left, covenant_id7);
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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
        },
    );
    let covenant_id9 = populate_single_output_genesis_covenant(&mux9);
    let horiz_right = compile_state(
        fix.horiz_right.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs { board: &board9, turn: 0, status: 0, pending_from_x: 0, pending_from_y: 3, pending_to_x: 3, pending_to_y: 3 },
    );
    run_route(&mux9, 5, 0, 3, 3, 3, &white, &fix.horiz_right, &horiz_right, covenant_id9);
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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
        },
    );
    let covenant_id11 = populate_single_output_genesis_covenant(&mux11);
    let diag_up_right = compile_state(
        fix.diag_up_right.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs { board: &board11, turn: 0, status: 0, pending_from_x: 0, pending_from_y: 0, pending_to_x: 3, pending_to_y: 3 },
    );
    run_route(&mux11, 6, 0, 0, 3, 3, &white, &fix.diag_up_right, &diag_up_right, covenant_id11);
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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
        },
    );
    let covenant_id12q = populate_single_output_genesis_covenant(&mux12q);
    let diag_up_right_queen = compile_state(
        fix.diag_up_right.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs { board: &board12q, turn: 0, status: 0, pending_from_x: 0, pending_from_y: 0, pending_to_x: 3, pending_to_y: 3 },
    );
    run_route(&mux12q, 6, 0, 0, 3, 3, &white, &fix.diag_up_right, &diag_up_right_queen, covenant_id12q);
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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
        },
    );
    let covenant_id13 = populate_single_output_genesis_covenant(&mux13);
    let diag_up_left = compile_state(
        fix.diag_up_left.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs { board: &board13, turn: 0, status: 0, pending_from_x: 7, pending_from_y: 0, pending_to_x: 4, pending_to_y: 3 },
    );
    run_route(&mux13, 7, 7, 0, 4, 3, &white, &fix.diag_up_left, &diag_up_left, covenant_id13);
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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
        },
    );
    let covenant_id15 = populate_single_output_genesis_covenant(&mux15);
    let diag_down_right = compile_state(
        fix.diag_down_right.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs { board: &board15, turn: 1, status: 0, pending_from_x: 0, pending_from_y: 7, pending_to_x: 3, pending_to_y: 4 },
    );
    run_route(&mux15, 8, 0, 7, 3, 4, &black, &fix.diag_down_right, &diag_down_right, covenant_id15);
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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
        },
    );
    let covenant_id17 = populate_single_output_genesis_covenant(&mux17);
    let diag_down_left = compile_state(
        fix.diag_down_left.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs { board: &board17, turn: 1, status: 0, pending_from_x: 7, pending_from_y: 7, pending_to_x: 4, pending_to_y: 4 },
    );
    run_route(&mux17, 9, 7, 7, 4, 4, &black, &fix.diag_down_left, &diag_down_left, covenant_id17);
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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
        },
    );
    let covenant_id19 = populate_single_output_genesis_covenant(&mux19);
    let king = compile_state(
        fix.king.source,
        &fix,
        &white.pubkey_hash,
        &black.pubkey_hash,
        GameStateArgs { board: &board19, turn: 0, status: 0, pending_from_x: 4, pending_from_y: 0, pending_to_x: 4, pending_to_y: 1 },
    );
    run_route(&mux19, 10, 4, 0, 4, 1, &white, &fix.king, &king, covenant_id19);
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
            pending_from_x: -1,
            pending_from_y: -1,
            pending_to_x: -1,
            pending_to_y: -1,
        },
    );
    run_worker_apply("king", &king, &mux20, covenant_id19, &fix.mux);
}
