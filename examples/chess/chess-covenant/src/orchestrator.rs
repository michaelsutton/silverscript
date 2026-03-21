use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

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

use crate::{
    castle_challenge_contract_path, castle_contract_path, diag_contract_path, horiz_contract_path, king_contract_path,
    knight_contract_path, league_contract_path, load_contract_source, mux_contract_path, pawn_contract_path, player_contract_path,
    settle_contract_path, vert_contract_path,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateWitness {
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
    pub hash: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChessTemplateFamily {
    pub league: TemplateWitness,
    pub player: TemplateWitness,
    pub mux: TemplateWitness,
    pub settle: TemplateWitness,
    pub pawn: TemplateWitness,
    pub knight: TemplateWitness,
    pub vert: TemplateWitness,
    pub horiz: TemplateWitness,
    pub diag: TemplateWitness,
    pub king: TemplateWitness,
    pub castle: TemplateWitness,
    pub castle_challenge: TemplateWitness,
    pub route_hashes: Vec<u8>,
    pub routes_commitment: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerKind {
    Pawn,
    Knight,
    Vert,
    Horiz,
    Diag,
    King,
    Castle,
    CastleChallenge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GameResult {
    WhiteWin,
    BlackWin,
    Draw,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerRequirement {
    None,
    Owner,
    SideToMove,
    WaitingOpponent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractRole {
    League,
    Player,
    Mux,
    Settle,
    Worker(WorkerKind),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedCall {
    pub role: ContractRole,
    pub function: &'static str,
    pub signer: SignerRequirement,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedOutput {
    pub role: ContractRole,
    pub count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxRecipe {
    pub name: &'static str,
    pub calls: Vec<PlannedCall>,
    pub outputs: Vec<PlannedOutput>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementRecipe {
    pub mux_step: TxRecipe,
    pub settle_step: TxRecipe,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChessTxPlanner {
    pub family: ChessTemplateFamily,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrchestratorError(pub String);

impl std::fmt::Display for OrchestratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for OrchestratorError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    White,
    Black,
}

const DEFAULT_MOVE_TIMEOUT: i64 = 600;

impl Side {
    fn other(self) -> Self {
        match self {
            Self::White => Self::Black,
            Self::Black => Self::White,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlayerHandle {
    pub name: String,
    pub pubkey_bytes: Vec<u8>,
    pub owner_hash: Vec<u8>,
    pub player_id: Option<Vec<u8>>,
    pub player_ref: Option<Vec<u8>>,
}

impl PlayerHandle {
    pub fn new(name: impl Into<String>, seed: u8) -> Self {
        let name = name.into();
        let pubkey_bytes = vec![seed; 32];
        let owner_hash = blake2b([name.as_bytes(), pubkey_bytes.as_slice()].concat().as_slice());
        Self { name, pubkey_bytes, owner_hash, player_id: None, player_ref: None }
    }
}

impl SigningPlayer {
    pub fn from_seed(name: impl Into<String>, seed: u8) -> Self {
        let name = name.into();
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[seed; 32]).expect("valid deterministic secret key");
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (x_only, _) = keypair.x_only_public_key();
        let pubkey_bytes = x_only.serialize().to_vec();
        let owner_hash = blake2b(&pubkey_bytes);
        Self { name, keypair, pubkey_bytes, owner_hash, player_id: None, player_ref: None }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlayerAccount {
    pub owner_name: String,
    pub owner_hash: Vec<u8>,
    pub player_id: Vec<u8>,
    pub player_ref: Vec<u8>,
    pub value: u64,
    pub open_games: i64,
    pub rating: i64,
    pub games: i64,
    pub wins: i64,
    pub draws: i64,
    pub losses: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GameSession {
    pub white_player_ref: Vec<u8>,
    pub black_player_ref: Vec<u8>,
    pub turn: Side,
    pub move_log: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerTransit {
    pub kind: WorkerKind,
    pub actor: Side,
    pub move_label: String,
    pub white_player_ref: Vec<u8>,
    pub black_player_ref: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementTicket {
    pub result: GameResult,
    pub white_player_ref: Vec<u8>,
    pub black_player_ref: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalUtxo {
    LeagueLane,
    Player(PlayerAccount),
    Mux(GameSession),
    Worker(WorkerTransit),
    Settle(SettlementTicket),
}

pub type LocalUtxoId = u64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OffchainMessageKind {
    GameInvite { proposed_white: String, proposed_black: String },
    InviteAccepted { white: String, black: String },
    GameStarted { white: String, black: String },
    MoveNotice { actor: String, worker: WorkerKind, move_label: String, mv: MoveSpec },
    SettlementRequest { result: GameResult },
    SettlementNotice { result: GameResult },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OffchainMessage {
    pub from: String,
    pub to: String,
    pub kind: OffchainMessageKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmittedTx {
    pub recipe_name: &'static str,
    pub consumed: Vec<LocalUtxoId>,
    pub produced: Vec<LocalUtxoId>,
    pub signer_names: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MoveSpec {
    pub from_x: i64,
    pub from_y: i64,
    pub to_x: i64,
    pub to_y: i64,
    pub promo_piece: i64,
}

impl MoveSpec {
    pub fn new(from_x: i64, from_y: i64, to_x: i64, to_y: i64) -> Self {
        Self { from_x, from_y, to_x, to_y, promo_piece: 0 }
    }

    pub fn with_promotion(from_x: i64, from_y: i64, to_x: i64, to_y: i64, promo_piece: i64) -> Self {
        Self { from_x, from_y, to_x, to_y, promo_piece }
    }

    pub fn label(self) -> String {
        format!("{}{}{}{}", file_char(self.from_x), rank_char(self.from_y), file_char(self.to_x), rank_char(self.to_y))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActualGameSnapshot {
    pub white_player_ref: Vec<u8>,
    pub black_player_ref: Vec<u8>,
    pub board: Vec<u8>,
    pub turn: Side,
    pub status: i64,
    pub move_log: Vec<String>,
}

#[derive(Clone)]
pub struct SigningPlayer {
    pub name: String,
    keypair: Keypair,
    pub pubkey_bytes: Vec<u8>,
    pub owner_hash: Vec<u8>,
    pub player_id: Option<Vec<u8>>,
    pub player_ref: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct LocalArena {
    pub planner: ChessTxPlanner,
    utxos: BTreeMap<LocalUtxoId, LocalUtxo>,
    mailboxes: BTreeMap<String, Vec<OffchainMessage>>,
    history: Vec<SubmittedTx>,
    next_utxo_id: LocalUtxoId,
    next_player_nonce: u32,
    base_rating: i64,
}

#[derive(Clone)]
struct TemplateFixture {
    source: &'static str,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    hash: Vec<u8>,
}

#[derive(Clone)]
struct ExecutionFixture {
    mux: TemplateFixture,
    settle: TemplateFixture,
    pawn: TemplateFixture,
    knight: TemplateFixture,
    vert: TemplateFixture,
    horiz: TemplateFixture,
    diag: TemplateFixture,
    king: TemplateFixture,
    castle: TemplateFixture,
    castle_challenge: TemplateFixture,
}

#[derive(Clone)]
struct PlayerStateData {
    owner_hash: Vec<u8>,
    player_id: Vec<u8>,
    value: u64,
    open_games: i64,
    rating: i64,
    games: i64,
    wins: i64,
    draws: i64,
    losses: i64,
}

struct PlayerStateArgs<'a> {
    league_hash: &'a [u8],
    player_hash: &'a [u8],
    mux_hash: &'a [u8],
    routes_commitment: &'a [u8],
    owner_hash: &'a [u8],
    player_id: &'a [u8],
    open_games: i64,
    rating: i64,
    games: i64,
    wins: i64,
    draws: i64,
    losses: i64,
}

#[derive(Clone)]
struct GameStateData {
    white_player: Vec<u8>,
    black_player: Vec<u8>,
    board: Vec<u8>,
    turn: i64,
    status: i64,
    move_timeout: i64,
    castle_rights: [u8; 4],
    en_passant_idx: i64,
    pending_src_idx: i64,
    pending_dst_idx: i64,
    pending_promo: i64,
    recent_castle: i64,
    draw_state: i64,
    move_log: Vec<String>,
}

pub struct TxArena {
    fix: ExecutionFixture,
    league_hash: Vec<u8>,
    base_rating: i64,
    player_hash: Vec<u8>,
    player_prefix: Vec<u8>,
    player_suffix: Vec<u8>,
    player_prefix_len: i64,
    player_suffix_len: i64,
    league: CompiledContract<'static>,
    covenant_id: Hash,
    players: BTreeMap<String, PlayerStateData>,
    game: Option<GameStateData>,
    messages: BTreeMap<String, Vec<OffchainMessage>>,
    history: Vec<SubmittedTx>,
    next_registration_index: u32,
}

#[derive(Clone)]
pub struct TxOrchestrator {
    pub player: SigningPlayer,
    arena: Rc<RefCell<TxArena>>,
}

impl ChessTxPlanner {
    pub fn load() -> Result<Self, OrchestratorError> {
        Ok(Self { family: load_template_family()? })
    }

    pub fn register_player_recipe(&self) -> TxRecipe {
        TxRecipe {
            name: "register_player",
            calls: vec![PlannedCall { role: ContractRole::League, function: "register_player", signer: SignerRequirement::Owner }],
            outputs: vec![
                PlannedOutput { role: ContractRole::League, count: 1 },
                PlannedOutput { role: ContractRole::Player, count: 1 },
            ],
        }
    }

    pub fn start_game_recipe(&self) -> TxRecipe {
        TxRecipe {
            name: "start_game",
            calls: vec![
                PlannedCall { role: ContractRole::Player, function: "start_game", signer: SignerRequirement::Owner },
                PlannedCall { role: ContractRole::Player, function: "delegate_start_game", signer: SignerRequirement::Owner },
            ],
            outputs: vec![PlannedOutput { role: ContractRole::Player, count: 2 }, PlannedOutput { role: ContractRole::Mux, count: 1 }],
        }
    }

    pub fn route_recipe(&self, worker: WorkerKind) -> TxRecipe {
        TxRecipe {
            name: "route",
            calls: vec![PlannedCall { role: ContractRole::Mux, function: "route", signer: SignerRequirement::SideToMove }],
            outputs: vec![PlannedOutput { role: ContractRole::Worker(worker), count: 1 }],
        }
    }

    pub fn worker_apply_recipe(&self, worker: WorkerKind) -> TxRecipe {
        TxRecipe {
            name: "worker_apply",
            calls: vec![PlannedCall { role: ContractRole::Worker(worker), function: "apply", signer: SignerRequirement::None }],
            outputs: vec![PlannedOutput { role: ContractRole::Mux, count: 1 }],
        }
    }

    pub fn mux_timeout_recipe(&self) -> TxRecipe {
        TxRecipe {
            name: "mux_timeout",
            calls: vec![PlannedCall { role: ContractRole::Mux, function: "timeout", signer: SignerRequirement::WaitingOpponent }],
            outputs: vec![PlannedOutput { role: ContractRole::Settle, count: 1 }],
        }
    }

    pub fn worker_timeout_recipe(&self, worker: WorkerKind) -> TxRecipe {
        TxRecipe {
            name: "worker_timeout",
            calls: vec![PlannedCall { role: ContractRole::Worker(worker), function: "timeout", signer: SignerRequirement::None }],
            outputs: vec![PlannedOutput { role: ContractRole::Settle, count: 1 }],
        }
    }

    pub fn settlement_recipe(&self, _result: GameResult) -> SettlementRecipe {
        SettlementRecipe {
            mux_step: TxRecipe {
                name: "mux_settle",
                calls: vec![PlannedCall { role: ContractRole::Mux, function: "settle", signer: SignerRequirement::None }],
                outputs: vec![PlannedOutput { role: ContractRole::Settle, count: 1 }],
            },
            settle_step: TxRecipe {
                name: "settle",
                calls: vec![
                    PlannedCall { role: ContractRole::Settle, function: "settle", signer: SignerRequirement::None },
                    PlannedCall { role: ContractRole::Player, function: "delegate_settle", signer: SignerRequirement::None },
                    PlannedCall { role: ContractRole::Player, function: "delegate_settle", signer: SignerRequirement::None },
                ],
                outputs: vec![PlannedOutput { role: ContractRole::Player, count: 2 }],
            },
        }
    }

    pub fn retire_recipe(&self) -> TxRecipe {
        TxRecipe {
            name: "retire",
            calls: vec![PlannedCall { role: ContractRole::Player, function: "retire", signer: SignerRequirement::Owner }],
            outputs: vec![],
        }
    }
}

impl LocalArena {
    pub fn new(planner: ChessTxPlanner) -> Self {
        let mut utxos = BTreeMap::new();
        utxos.insert(1, LocalUtxo::LeagueLane);
        Self {
            planner,
            utxos,
            mailboxes: BTreeMap::new(),
            history: Vec::new(),
            next_utxo_id: 2,
            next_player_nonce: 0,
            base_rating: 1200,
        }
    }

    pub fn history(&self) -> &[SubmittedTx] {
        &self.history
    }

    pub fn inbox(&self, player: &PlayerHandle) -> &[OffchainMessage] {
        self.mailboxes.get(&player.name).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn drain_inbox(&mut self, player: &PlayerHandle) -> Vec<OffchainMessage> {
        self.mailboxes.remove(&player.name).unwrap_or_default()
    }

    pub fn register_player(&mut self, player: &mut PlayerHandle) -> Result<SubmittedTx, OrchestratorError> {
        if player.player_ref.is_some() {
            return Err(OrchestratorError(format!("{} is already registered", player.name)));
        }

        let league_id = self
            .utxos
            .iter()
            .find_map(|(id, utxo)| matches!(utxo, LocalUtxo::LeagueLane).then_some(*id))
            .ok_or_else(|| OrchestratorError("missing league lane".to_string()))?;

        let player_id = derive_player_id(self.next_player_nonce, &player.owner_hash);
        self.next_player_nonce += 1;
        let player_ref = blake2b([player.owner_hash.as_slice(), player_id.as_slice()].concat().as_slice());

        let account = PlayerAccount {
            owner_name: player.name.clone(),
            owner_hash: player.owner_hash.clone(),
            player_id: player_id.clone(),
            player_ref: player_ref.clone(),
            value: 1_000,
            open_games: 0,
            rating: self.base_rating,
            games: 0,
            wins: 0,
            draws: 0,
            losses: 0,
        };

        player.player_id = Some(player_id);
        player.player_ref = Some(player_ref);

        let next_league_id = self.alloc_utxo(LocalUtxo::LeagueLane);
        let next_player_id = self.alloc_utxo(LocalUtxo::Player(account));
        self.utxos.remove(&league_id);

        let submission = SubmittedTx {
            recipe_name: self.planner.register_player_recipe().name,
            consumed: vec![league_id],
            produced: vec![next_league_id, next_player_id],
            signer_names: vec![player.name.clone()],
        };
        self.history.push(submission.clone());
        Ok(submission)
    }

    pub fn send_game_invite(&mut self, white: &PlayerHandle, black: &PlayerHandle) -> Result<(), OrchestratorError> {
        self.require_registered(white)?;
        self.require_registered(black)?;
        self.push_message(
            &black.name,
            OffchainMessage {
                from: white.name.clone(),
                to: black.name.clone(),
                kind: OffchainMessageKind::GameInvite { proposed_white: white.name.clone(), proposed_black: black.name.clone() },
            },
        );
        Ok(())
    }

    pub fn start_game(&mut self, white: &PlayerHandle, black: &PlayerHandle) -> Result<SubmittedTx, OrchestratorError> {
        let white_ref = white.player_ref.clone().ok_or_else(|| OrchestratorError("white player is not registered".to_string()))?;
        let black_ref = black.player_ref.clone().ok_or_else(|| OrchestratorError("black player is not registered".to_string()))?;

        let white_id = self.find_player_utxo_id(&white_ref)?;
        let black_id = self.find_player_utxo_id(&black_ref)?;
        let mut white_account = self.player_account(&white_ref)?;
        let mut black_account = self.player_account(&black_ref)?;

        white_account.open_games += 1;
        black_account.open_games += 1;

        self.utxos.remove(&white_id);
        self.utxos.remove(&black_id);

        let next_white_id = self.alloc_utxo(LocalUtxo::Player(white_account));
        let next_black_id = self.alloc_utxo(LocalUtxo::Player(black_account));
        let mux_id = self.alloc_utxo(LocalUtxo::Mux(GameSession {
            white_player_ref: white_ref.clone(),
            black_player_ref: black_ref.clone(),
            turn: Side::White,
            move_log: Vec::new(),
        }));

        let submission = SubmittedTx {
            recipe_name: self.planner.start_game_recipe().name,
            consumed: vec![white_id, black_id],
            produced: vec![next_white_id, next_black_id, mux_id],
            signer_names: vec![white.name.clone(), black.name.clone()],
        };
        self.history.push(submission.clone());
        Ok(submission)
    }

    pub fn submit_move(
        &mut self,
        actor: &PlayerHandle,
        worker: WorkerKind,
        move_label: impl Into<String>,
    ) -> Result<Vec<SubmittedTx>, OrchestratorError> {
        let actor_ref = actor.player_ref.clone().ok_or_else(|| OrchestratorError(format!("{} is not registered", actor.name)))?;
        let move_label = move_label.into();
        let (mux_id, mux) = self.active_mux()?;

        let actor_side = if actor_ref == mux.white_player_ref {
            Side::White
        } else if actor_ref == mux.black_player_ref {
            Side::Black
        } else {
            return Err(OrchestratorError(format!("{} is not part of the current game", actor.name)));
        };

        if actor_side != mux.turn {
            return Err(OrchestratorError(format!("it is not {}'s turn", actor.name)));
        }

        self.utxos.remove(&mux_id);
        let worker_id = self.alloc_utxo(LocalUtxo::Worker(WorkerTransit {
            kind: worker,
            actor: actor_side,
            move_label: move_label.clone(),
            white_player_ref: mux.white_player_ref.clone(),
            black_player_ref: mux.black_player_ref.clone(),
        }));
        let route_tx = SubmittedTx {
            recipe_name: self.planner.route_recipe(worker).name,
            consumed: vec![mux_id],
            produced: vec![worker_id],
            signer_names: vec![actor.name.clone()],
        };
        self.history.push(route_tx.clone());

        let worker_state = match self.utxos.remove(&worker_id) {
            Some(LocalUtxo::Worker(worker_state)) => worker_state,
            _ => return Err(OrchestratorError("missing worker transit".to_string())),
        };

        let next_turn = worker_state.actor.other();
        let mut move_log = mux.move_log.clone();
        move_log.push(format!("{}:{:?}:{}", actor.name, worker, move_label));
        let next_mux_id = self.alloc_utxo(LocalUtxo::Mux(GameSession {
            white_player_ref: worker_state.white_player_ref.clone(),
            black_player_ref: worker_state.black_player_ref.clone(),
            turn: next_turn,
            move_log,
        }));
        let apply_tx = SubmittedTx {
            recipe_name: self.planner.worker_apply_recipe(worker).name,
            consumed: vec![worker_id],
            produced: vec![next_mux_id],
            signer_names: vec![],
        };
        self.history.push(apply_tx.clone());

        let recipient = if actor_side == Side::White {
            self.owner_name(&worker_state.black_player_ref)?
        } else {
            self.owner_name(&worker_state.white_player_ref)?
        };
        self.push_message(
            &recipient,
            OffchainMessage {
                from: actor.name.clone(),
                to: recipient.clone(),
                kind: OffchainMessageKind::MoveNotice {
                    actor: actor.name.clone(),
                    worker,
                    move_label,
                    mv: MoveSpec::new(-1, -1, -1, -1),
                },
            },
        );

        Ok(vec![route_tx, apply_tx])
    }

    pub fn settle_game(
        &mut self,
        white: &PlayerHandle,
        black: &PlayerHandle,
        result: GameResult,
    ) -> Result<Vec<SubmittedTx>, OrchestratorError> {
        self.require_registered(white)?;
        self.require_registered(black)?;
        let (mux_id, mux) = self.active_mux()?;
        let white_ref = white.player_ref.clone().ok_or_else(|| OrchestratorError("white player is not registered".to_string()))?;
        let black_ref = black.player_ref.clone().ok_or_else(|| OrchestratorError("black player is not registered".to_string()))?;
        if mux.white_player_ref != white_ref || mux.black_player_ref != black_ref {
            return Err(OrchestratorError("active mux does not match provided players".to_string()));
        }

        self.utxos.remove(&mux_id);
        let settle_id = self.alloc_utxo(LocalUtxo::Settle(SettlementTicket {
            result,
            white_player_ref: mux.white_player_ref.clone(),
            black_player_ref: mux.black_player_ref.clone(),
        }));
        let mux_tx = SubmittedTx {
            recipe_name: self.planner.settlement_recipe(result).mux_step.name,
            consumed: vec![mux_id],
            produced: vec![settle_id],
            signer_names: vec![],
        };
        self.history.push(mux_tx.clone());

        let white_player_id = self.find_player_utxo_id(&white_ref)?;
        let black_player_id = self.find_player_utxo_id(&black_ref)?;
        let mut white_account = self.player_account(&white_ref)?;
        let mut black_account = self.player_account(&black_ref)?;
        if white_account.open_games <= 0 || black_account.open_games <= 0 {
            return Err(OrchestratorError("cannot settle players without open games".to_string()));
        }

        white_account.open_games -= 1;
        black_account.open_games -= 1;
        white_account.games += 1;
        black_account.games += 1;

        let (white_actual, black_actual) = match result {
            GameResult::WhiteWin => {
                white_account.wins += 1;
                black_account.losses += 1;
                (1000, 0)
            }
            GameResult::BlackWin => {
                white_account.losses += 1;
                black_account.wins += 1;
                (0, 1000)
            }
            GameResult::Draw => {
                white_account.draws += 1;
                black_account.draws += 1;
                (500, 500)
            }
        };

        let white_old_rating = white_account.rating;
        let black_old_rating = black_account.rating;
        white_account.rating = approx_updated_rating(white_old_rating, black_old_rating, white_actual);
        black_account.rating = approx_updated_rating(black_old_rating, white_old_rating, black_actual);

        let stake = 1_000u64;
        match result {
            GameResult::WhiteWin => {
                white_account.value += stake;
            }
            GameResult::BlackWin => {
                black_account.value += stake;
            }
            GameResult::Draw => {
                let white_share = stake / 2;
                let black_share = stake - white_share;
                white_account.value += white_share;
                black_account.value += black_share;
            }
        }

        self.utxos.remove(&settle_id);
        self.utxos.remove(&white_player_id);
        self.utxos.remove(&black_player_id);

        let next_white_id = self.alloc_utxo(LocalUtxo::Player(white_account));
        let next_black_id = self.alloc_utxo(LocalUtxo::Player(black_account));
        let settle_tx = SubmittedTx {
            recipe_name: self.planner.settlement_recipe(result).settle_step.name,
            consumed: vec![settle_id, white_player_id, black_player_id],
            produced: vec![next_white_id, next_black_id],
            signer_names: vec![],
        };
        self.history.push(settle_tx.clone());

        self.push_message(
            &white.name,
            OffchainMessage {
                from: "arena".to_string(),
                to: white.name.clone(),
                kind: OffchainMessageKind::SettlementNotice { result },
            },
        );
        self.push_message(
            &black.name,
            OffchainMessage {
                from: "arena".to_string(),
                to: black.name.clone(),
                kind: OffchainMessageKind::SettlementNotice { result },
            },
        );

        Ok(vec![mux_tx, settle_tx])
    }

    pub fn retire_player(&mut self, player: &PlayerHandle) -> Result<SubmittedTx, OrchestratorError> {
        let player_ref = player.player_ref.clone().ok_or_else(|| OrchestratorError(format!("{} is not registered", player.name)))?;
        let player_id = self.find_player_utxo_id(&player_ref)?;
        let account = self.player_account(&player_ref)?;
        if account.open_games != 0 {
            return Err(OrchestratorError(format!("{} still has open games", player.name)));
        }
        self.utxos.remove(&player_id);
        let submission = SubmittedTx {
            recipe_name: self.planner.retire_recipe().name,
            consumed: vec![player_id],
            produced: vec![],
            signer_names: vec![player.name.clone()],
        };
        self.history.push(submission.clone());
        Ok(submission)
    }

    pub fn player_account_snapshot(&self, player: &PlayerHandle) -> Result<PlayerAccount, OrchestratorError> {
        let player_ref = player.player_ref.clone().ok_or_else(|| OrchestratorError(format!("{} is not registered", player.name)))?;
        self.player_account(&player_ref)
    }

    pub fn active_game_snapshot(&self) -> Option<GameSession> {
        self.utxos.values().find_map(|utxo| match utxo {
            LocalUtxo::Mux(game) => Some(game.clone()),
            _ => None,
        })
    }

    fn alloc_utxo(&mut self, utxo: LocalUtxo) -> LocalUtxoId {
        let id = self.next_utxo_id;
        self.next_utxo_id += 1;
        self.utxos.insert(id, utxo);
        id
    }

    fn push_message(&mut self, recipient: &str, message: OffchainMessage) {
        self.mailboxes.entry(recipient.to_string()).or_default().push(message);
    }

    fn require_registered(&self, player: &PlayerHandle) -> Result<(), OrchestratorError> {
        if player.player_ref.is_none() || player.player_id.is_none() {
            return Err(OrchestratorError(format!("{} is not registered", player.name)));
        }
        Ok(())
    }

    fn find_player_utxo_id(&self, player_ref: &[u8]) -> Result<LocalUtxoId, OrchestratorError> {
        self.utxos
            .iter()
            .find_map(|(id, utxo)| match utxo {
                LocalUtxo::Player(account) if account.player_ref == player_ref => Some(*id),
                _ => None,
            })
            .ok_or_else(|| OrchestratorError("missing player UTXO".to_string()))
    }

    fn player_account(&self, player_ref: &[u8]) -> Result<PlayerAccount, OrchestratorError> {
        self.utxos
            .values()
            .find_map(|utxo| match utxo {
                LocalUtxo::Player(account) if account.player_ref == player_ref => Some(account.clone()),
                _ => None,
            })
            .ok_or_else(|| OrchestratorError("missing player account".to_string()))
    }

    fn active_mux(&self) -> Result<(LocalUtxoId, GameSession), OrchestratorError> {
        self.utxos
            .iter()
            .find_map(|(id, utxo)| match utxo {
                LocalUtxo::Mux(game) => Some((*id, game.clone())),
                _ => None,
            })
            .ok_or_else(|| OrchestratorError("missing active mux".to_string()))
    }

    fn owner_name(&self, player_ref: &[u8]) -> Result<String, OrchestratorError> {
        Ok(self.player_account(player_ref)?.owner_name)
    }
}

impl TxOrchestrator {
    pub fn new(name: impl Into<String>, seed: u8, arena: Rc<RefCell<TxArena>>) -> Self {
        Self { player: SigningPlayer::from_seed(name, seed), arena }
    }

    pub fn inbox(&self) -> Vec<OffchainMessage> {
        self.arena.borrow_mut().drain_messages(&self.player.name)
    }

    pub fn register(&mut self) -> Result<(), OrchestratorError> {
        self.arena.borrow_mut().register_player(&mut self.player)
    }

    pub fn send_game_invite(&self, other: &TxOrchestrator) -> Result<(), OrchestratorError> {
        self.arena.borrow_mut().send_game_invite(&self.player, &other.player)
    }

    pub fn accept_game_invite(&self, other: &TxOrchestrator) -> Result<(), OrchestratorError> {
        self.arena.borrow_mut().accept_game_invite(&self.player, &other.player)
    }

    pub fn start_game(&self, other: &TxOrchestrator) -> Result<(), OrchestratorError> {
        self.arena.borrow_mut().start_game(&self.player, &other.player)
    }

    pub fn submit_move(&self, mv: MoveSpec) -> Result<Vec<SubmittedTx>, OrchestratorError> {
        self.arena.borrow_mut().submit_move(&self.player, mv)
    }

    pub fn surrender(&self) -> Result<(), OrchestratorError> {
        self.arena.borrow_mut().surrender(&self.player)
    }

    pub fn request_settlement(&self, other: &TxOrchestrator, result: GameResult) -> Result<(), OrchestratorError> {
        self.arena.borrow_mut().request_settlement(&self.player, &other.player, result)
    }

    pub fn settle(&self, other: &TxOrchestrator, result: GameResult) -> Result<(), OrchestratorError> {
        self.arena.borrow_mut().settle_game(&self.player, &other.player, result)
    }

    pub fn retire(&self) -> Result<(), OrchestratorError> {
        self.arena.borrow_mut().retire_player(&self.player)
    }
}

impl TxArena {
    pub fn new() -> Result<Self, OrchestratorError> {
        let fix = build_execution_fixture();
        let league_hash = vec![0x11u8; 32];
        let admin = vec![0x33u8; 32];
        let base_rating = 1200;
        let routes_commitment = routes_commitment(&packed_execution_route_hashes(&fix));
        let player_template = compile_player_state(
            player_static_source(),
            PlayerStateArgs {
                league_hash: &[0x11u8; 32],
                player_hash: &[0x22u8; 32],
                mux_hash: &fix.mux.hash,
                routes_commitment: &routes_commitment,
                owner_hash: &[0x44u8; 32],
                player_id: &[0x55u8; 32],
                open_games: 0,
                rating: base_rating,
                games: 0,
                wins: 0,
                draws: 0,
                losses: 0,
            },
        );
        let layout = player_template.state_layout;
        let player_prefix = player_template.script[..layout.start].to_vec();
        let player_suffix = player_template.script[layout.start + layout.len..].to_vec();
        let player_hash = blake2b([player_prefix.as_slice(), player_suffix.as_slice()].concat().as_slice());
        let league = compile_league_state(
            league_static_source(),
            &league_hash,
            &player_hash,
            &fix.mux.hash,
            &routes_commitment,
            base_rating,
            &admin,
        );
        let covenant_id = populate_single_output_genesis_covenant(&league);

        Ok(Self {
            fix,
            league_hash,
            base_rating,
            player_hash,
            player_prefix,
            player_suffix,
            player_prefix_len: layout.start as i64,
            player_suffix_len: (player_template.script.len() - (layout.start + layout.len)) as i64,
            league,
            covenant_id,
            players: BTreeMap::new(),
            game: None,
            messages: BTreeMap::new(),
            history: Vec::new(),
            next_registration_index: 7,
        })
    }

    pub fn shared() -> Result<Rc<RefCell<Self>>, OrchestratorError> {
        Ok(Rc::new(RefCell::new(Self::new()?)))
    }

    pub fn drain_messages(&mut self, name: &str) -> Vec<OffchainMessage> {
        self.messages.remove(name).unwrap_or_default()
    }

    pub fn history(&self) -> &[SubmittedTx] {
        &self.history
    }

    pub fn player_account_snapshot(&self, player: &SigningPlayer) -> Result<PlayerAccount, OrchestratorError> {
        let player_ref = player.player_ref.clone().ok_or_else(|| OrchestratorError(format!("{} is not registered", player.name)))?;
        self.player_account(&player_ref)
    }

    pub fn active_game_snapshot(&self) -> Option<ActualGameSnapshot> {
        self.game.as_ref().map(|game| ActualGameSnapshot {
            white_player_ref: game.white_player.clone(),
            black_player_ref: game.black_player.clone(),
            board: game.board.clone(),
            turn: side_from_turn(game.turn),
            status: game.status,
            move_log: game.move_log.clone(),
        })
    }

    pub fn register_player(&mut self, player: &mut SigningPlayer) -> Result<(), OrchestratorError> {
        let index = self.next_registration_index;
        self.next_registration_index += 1;
        let txid = [0xabu8; 32];
        let player_id = blake2b([b"LeaguePlayerId".as_slice(), &txid, &index.to_le_bytes()].concat().as_slice());
        let player_ref = blake2b([player.owner_hash.as_slice(), player_id.as_slice()].concat().as_slice());

        let registered = compile_player_state(
            player_static_source(),
            PlayerStateArgs {
                league_hash: &self.league_hash,
                player_hash: &self.player_hash,
                mux_hash: &self.fix.mux.hash,
                routes_commitment: &routes_commitment(&packed_execution_route_hashes(&self.fix)),
                owner_hash: &player.owner_hash,
                player_id: &player_id,
                open_games: 0,
                rating: self.base_rating,
                games: 0,
                wins: 0,
                draws: 0,
                losses: 0,
            },
        );

        let league_input = TransactionInput {
            previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes(txid), index },
            signature_script: vec![],
            sequence: 0,
            sig_op_count: 1,
        };
        let placeholder = entry_sigscript(
            &self.league,
            "register_player",
            vec![
                Expr::bytes(vec![0u8; 65]),
                Expr::bytes(player.pubkey_bytes.clone()),
                Expr::bytes(self.player_prefix.clone()),
                Expr::bytes(self.player_suffix.clone()),
            ],
        );
        let outputs = vec![covenant_output(&self.league, 0, self.covenant_id), covenant_output(&registered, 0, self.covenant_id)];
        let entries = vec![covenant_utxo(&self.league, self.covenant_id)];
        let mut tx = Transaction::new(1, vec![league_input], outputs, 0, Default::default(), 0, vec![]);
        tx.inputs[0].signature_script = placeholder;
        let sig = sign_tx_input_schnorr(&tx, &entries, 0, player);
        tx.inputs[0].signature_script = entry_sigscript(
            &self.league,
            "register_player",
            vec![
                Expr::bytes(sig),
                Expr::bytes(player.pubkey_bytes.clone()),
                Expr::bytes(self.player_prefix.clone()),
                Expr::bytes(self.player_suffix.clone()),
            ],
        );
        execute_input_with_covenants(tx, entries, 0).map_err(|err| OrchestratorError(format!("register failed: {err}")))?;

        player.player_id = Some(player_id.clone());
        player.player_ref = Some(player_ref.clone());
        self.players.insert(
            player.name.clone(),
            PlayerStateData {
                owner_hash: player.owner_hash.clone(),
                player_id,
                value: 1_000,
                open_games: 0,
                rating: self.base_rating,
                games: 0,
                wins: 0,
                draws: 0,
                losses: 0,
            },
        );
        self.history.push(SubmittedTx {
            recipe_name: "register_player",
            consumed: vec![],
            produced: vec![],
            signer_names: vec![player.name.clone()],
        });
        Ok(())
    }

    pub fn send_game_invite(&mut self, white: &SigningPlayer, black: &SigningPlayer) -> Result<(), OrchestratorError> {
        self.require_registered(white)?;
        self.require_registered(black)?;
        self.push_message(
            &black.name,
            OffchainMessage {
                from: white.name.clone(),
                to: black.name.clone(),
                kind: OffchainMessageKind::GameInvite { proposed_white: white.name.clone(), proposed_black: black.name.clone() },
            },
        );
        Ok(())
    }

    pub fn accept_game_invite(&mut self, black: &SigningPlayer, white: &SigningPlayer) -> Result<(), OrchestratorError> {
        self.require_registered(white)?;
        self.require_registered(black)?;
        self.push_message(
            &white.name,
            OffchainMessage {
                from: black.name.clone(),
                to: white.name.clone(),
                kind: OffchainMessageKind::InviteAccepted { white: white.name.clone(), black: black.name.clone() },
            },
        );
        Ok(())
    }

    pub fn start_game(&mut self, white: &SigningPlayer, black: &SigningPlayer) -> Result<(), OrchestratorError> {
        let white_state = self.players.get(&white.name).cloned().ok_or_else(|| OrchestratorError("missing white".to_string()))?;
        let black_state = self.players.get(&black.name).cloned().ok_or_else(|| OrchestratorError("missing black".to_string()))?;
        let white_contract = self.compile_player(&white_state);
        let black_contract = self.compile_player(&black_state);

        let mut next_white = white_state.clone();
        next_white.open_games += 1;
        let mut next_black = black_state.clone();
        next_black.open_games += 1;
        let next_white_contract = self.compile_player(&next_white);
        let next_black_contract = self.compile_player(&next_black);

        let white_ref = white.player_ref.clone().ok_or_else(|| OrchestratorError("white missing player ref".to_string()))?;
        let black_ref = black.player_ref.clone().ok_or_else(|| OrchestratorError("black missing player ref".to_string()))?;
        let opening = GameStateData {
            white_player: white_ref,
            black_player: black_ref,
            board: standard_board(),
            turn: 0,
            status: 0,
            move_timeout: DEFAULT_MOVE_TIMEOUT,
            castle_rights: [1, 1, 1, 1],
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 3,
            move_log: Vec::new(),
        };
        let opening_mux = self.compile_mux(&opening);

        let white_placeholder = entry_sigscript(
            &white_contract,
            "start_game",
            vec![
                Expr::bytes(vec![0u8; 65]),
                Expr::bytes(white.pubkey_bytes.clone()),
                Expr::int(0),
                Expr::int(self.player_prefix_len),
                Expr::int(self.player_suffix_len),
                Expr::bytes(packed_execution_route_hashes(&self.fix)),
                Expr::int(DEFAULT_MOVE_TIMEOUT),
                Expr::bytes(self.fix.mux.prefix.clone()),
                Expr::bytes(self.fix.mux.suffix.clone()),
            ],
        );
        let black_placeholder = entry_sigscript(
            &black_contract,
            "delegate_start_game",
            vec![
                Expr::bytes(vec![0u8; 65]),
                Expr::bytes(black.pubkey_bytes.clone()),
                Expr::int(DEFAULT_MOVE_TIMEOUT),
                Expr::int(self.player_prefix_len),
                Expr::int(self.player_suffix_len),
            ],
        );
        let outputs = vec![
            covenant_output_with_value(&next_white_contract, 0, self.covenant_id, next_white.value),
            covenant_output_with_value(&next_black_contract, 0, self.covenant_id, next_black.value),
            covenant_output(&opening_mux, 0, self.covenant_id),
        ];
        let entries = vec![
            covenant_utxo_with_value(&white_contract, self.covenant_id, white_state.value),
            covenant_utxo_with_value(&black_contract, self.covenant_id, black_state.value),
        ];
        let mut tx = Transaction::new(
            1,
            vec![tx_input(0, white_placeholder, 1), tx_input(1, black_placeholder, 1)],
            outputs,
            0,
            Default::default(),
            0,
            vec![],
        );
        let white_sig = sign_tx_input_schnorr(&tx, &entries, 0, white);
        let black_sig = sign_tx_input_schnorr(&tx, &entries, 1, black);
        tx.inputs[0].signature_script = entry_sigscript(
            &white_contract,
            "start_game",
            vec![
                Expr::bytes(white_sig),
                Expr::bytes(white.pubkey_bytes.clone()),
                Expr::int(0),
                Expr::int(self.player_prefix_len),
                Expr::int(self.player_suffix_len),
                Expr::bytes(packed_execution_route_hashes(&self.fix)),
                Expr::int(DEFAULT_MOVE_TIMEOUT),
                Expr::bytes(self.fix.mux.prefix.clone()),
                Expr::bytes(self.fix.mux.suffix.clone()),
            ],
        );
        tx.inputs[1].signature_script = entry_sigscript(
            &black_contract,
            "delegate_start_game",
            vec![
                Expr::bytes(black_sig),
                Expr::bytes(black.pubkey_bytes.clone()),
                Expr::int(DEFAULT_MOVE_TIMEOUT),
                Expr::int(self.player_prefix_len),
                Expr::int(self.player_suffix_len),
            ],
        );
        execute_input_with_covenants(tx.clone(), entries.clone(), 0)
            .map_err(|err| OrchestratorError(format!("start leader failed: {err}")))?;
        execute_input_with_covenants(tx, entries, 1).map_err(|err| OrchestratorError(format!("start delegate failed: {err}")))?;

        self.players.insert(white.name.clone(), next_white);
        self.players.insert(black.name.clone(), next_black);
        self.game = Some(opening);
        self.push_message(
            &white.name,
            OffchainMessage {
                from: "arena".to_string(),
                to: white.name.clone(),
                kind: OffchainMessageKind::GameStarted { white: white.name.clone(), black: black.name.clone() },
            },
        );
        self.push_message(
            &black.name,
            OffchainMessage {
                from: "arena".to_string(),
                to: black.name.clone(),
                kind: OffchainMessageKind::GameStarted { white: white.name.clone(), black: black.name.clone() },
            },
        );
        self.history.push(SubmittedTx {
            recipe_name: "start_game",
            consumed: vec![],
            produced: vec![],
            signer_names: vec![white.name.clone(), black.name.clone()],
        });
        Ok(())
    }

    pub fn submit_move(&mut self, actor: &SigningPlayer, mv: MoveSpec) -> Result<Vec<SubmittedTx>, OrchestratorError> {
        let game = self.game.clone().ok_or_else(|| OrchestratorError("missing game".to_string()))?;
        let actor_ref = actor.player_ref.clone().ok_or_else(|| OrchestratorError(format!("{} missing player ref", actor.name)))?;
        let actor_side = if actor_ref == game.white_player {
            Side::White
        } else if actor_ref == game.black_player {
            Side::Black
        } else {
            return Err(OrchestratorError(format!("{} is not part of the active game", actor.name)));
        };
        if actor_side != side_from_turn(game.turn) {
            return Err(OrchestratorError(format!("it is not {}'s turn", actor.name)));
        }

        let worker = determine_worker(&game.board, mv)?;
        let target = self.worker_fixture(worker);
        let active = self.compile_mux(&game);
        let pending = pending_state_for_move(&game, mv);
        let worker_contract = self.compile_worker(target.source, &pending);
        let placeholder = entry_sigscript(
            &active,
            "route",
            vec![
                Expr::int(worker_selector(worker)),
                Expr::int(mv.from_x),
                Expr::int(mv.from_y),
                Expr::int(mv.to_x),
                Expr::int(mv.to_y),
                Expr::int(mv.promo_piece),
                Expr::int(0),
                Expr::bytes(vec![0u8; 65]),
                Expr::bytes(actor.pubkey_bytes.clone()),
                Expr::bytes(actor.player_id.clone().ok_or_else(|| OrchestratorError("missing player id".to_string()))?),
                Expr::bytes(target.prefix.clone()),
                Expr::bytes(target.suffix.clone()),
            ],
        );
        let outputs = vec![covenant_output(&worker_contract, 0, self.covenant_id)];
        let entries = vec![covenant_utxo(&active, self.covenant_id)];
        let mut route_tx = Transaction::new(1, vec![tx_input(0, placeholder, 1)], outputs, 0, Default::default(), 0, vec![]);
        let sig = sign_tx_input_schnorr(&route_tx, &entries, 0, actor);
        route_tx.inputs[0].signature_script = entry_sigscript(
            &active,
            "route",
            vec![
                Expr::int(worker_selector(worker)),
                Expr::int(mv.from_x),
                Expr::int(mv.from_y),
                Expr::int(mv.to_x),
                Expr::int(mv.to_y),
                Expr::int(mv.promo_piece),
                Expr::int(0),
                Expr::bytes(sig),
                Expr::bytes(actor.pubkey_bytes.clone()),
                Expr::bytes(actor.player_id.clone().ok_or_else(|| OrchestratorError("missing player id".to_string()))?),
                Expr::bytes(target.prefix.clone()),
                Expr::bytes(target.suffix.clone()),
            ],
        );
        execute_input_with_covenants(route_tx, entries, 0).map_err(|err| OrchestratorError(format!("route failed: {err}")))?;

        let next = apply_move_to_state(&game, mv)?;
        let next_mux = self.compile_mux(&next);
        let apply_sigscript = entry_sigscript(
            &worker_contract,
            "apply",
            vec![Expr::bytes(self.fix.mux.prefix.clone()), Expr::bytes(self.fix.mux.suffix.clone())],
        );
        let apply_tx = Transaction::new(
            1,
            vec![tx_input(0, apply_sigscript, 0)],
            vec![covenant_output(&next_mux, 0, self.covenant_id)],
            0,
            Default::default(),
            0,
            vec![],
        );
        let apply_entries = vec![covenant_utxo(&worker_contract, self.covenant_id)];
        execute_input_with_covenants(apply_tx, apply_entries, 0).map_err(|err| OrchestratorError(format!("apply failed: {err}")))?;

        let move_label = mv.label();
        let recipient = if actor_side == Side::White {
            self.players
                .iter()
                .find_map(|(name, state)| {
                    (blake2b([state.owner_hash.as_slice(), state.player_id.as_slice()].concat().as_slice()) == game.black_player)
                        .then_some(name.clone())
                })
                .ok_or_else(|| OrchestratorError("missing black owner".to_string()))?
        } else {
            self.players
                .iter()
                .find_map(|(name, state)| {
                    (blake2b([state.owner_hash.as_slice(), state.player_id.as_slice()].concat().as_slice()) == game.white_player)
                        .then_some(name.clone())
                })
                .ok_or_else(|| OrchestratorError("missing white owner".to_string()))?
        };
        self.push_message(
            &recipient,
            OffchainMessage {
                from: actor.name.clone(),
                to: recipient.clone(),
                kind: OffchainMessageKind::MoveNotice { actor: actor.name.clone(), worker, move_label: move_label.clone(), mv },
            },
        );
        self.game = Some(next);

        let submissions = vec![
            SubmittedTx {
                recipe_name: self.planner().route_recipe(worker).name,
                consumed: vec![],
                produced: vec![],
                signer_names: vec![actor.name.clone()],
            },
            SubmittedTx {
                recipe_name: self.planner().worker_apply_recipe(worker).name,
                consumed: vec![],
                produced: vec![],
                signer_names: vec![],
            },
        ];
        self.history.extend(submissions.clone());
        Ok(submissions)
    }

    pub fn surrender(&mut self, actor: &SigningPlayer) -> Result<(), OrchestratorError> {
        let game = self.game.clone().ok_or_else(|| OrchestratorError("missing game".to_string()))?;
        let actor_ref = actor.player_ref.clone().ok_or_else(|| OrchestratorError(format!("{} missing player ref", actor.name)))?;
        let actor_side = if actor_ref == game.white_player {
            Side::White
        } else if actor_ref == game.black_player {
            Side::Black
        } else {
            return Err(OrchestratorError(format!("{} is not part of the active game", actor.name)));
        };
        if actor_side != side_from_turn(game.turn) {
            return Err(OrchestratorError(format!("it is not {}'s turn", actor.name)));
        }

        let active = self.compile_mux(&game);
        let next = GameStateData {
            white_player: game.white_player.clone(),
            black_player: game.black_player.clone(),
            board: game.board.clone(),
            turn: game.turn,
            status: if game.turn == 0 { 2 } else { 1 },
            move_timeout: game.move_timeout,
            castle_rights: game.castle_rights,
            en_passant_idx: -1,
            pending_src_idx: -1,
            pending_dst_idx: -1,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 3,
            move_log: game.move_log.clone(),
        };
        let terminal = self.compile_mux(&next);
        let placeholder = entry_sigscript(
            &active,
            "route",
            vec![
                Expr::int(8),
                Expr::int(-1),
                Expr::int(-1),
                Expr::int(-1),
                Expr::int(-1),
                Expr::int(0),
                Expr::int(3),
                Expr::bytes(vec![0u8; 65]),
                Expr::bytes(actor.pubkey_bytes.clone()),
                Expr::bytes(actor.player_id.clone().ok_or_else(|| OrchestratorError("missing player id".to_string()))?),
                Expr::bytes(self.fix.mux.prefix.clone()),
                Expr::bytes(self.fix.mux.suffix.clone()),
            ],
        );
        let outputs = vec![covenant_output(&terminal, 0, self.covenant_id)];
        let entries = vec![covenant_utxo(&active, self.covenant_id)];
        let mut tx = Transaction::new(1, vec![tx_input(0, placeholder, 1)], outputs, 0, Default::default(), 0, vec![]);
        let sig = sign_tx_input_schnorr(&tx, &entries, 0, actor);
        tx.inputs[0].signature_script = entry_sigscript(
            &active,
            "route",
            vec![
                Expr::int(8),
                Expr::int(-1),
                Expr::int(-1),
                Expr::int(-1),
                Expr::int(-1),
                Expr::int(0),
                Expr::int(3),
                Expr::bytes(sig),
                Expr::bytes(actor.pubkey_bytes.clone()),
                Expr::bytes(actor.player_id.clone().ok_or_else(|| OrchestratorError("missing player id".to_string()))?),
                Expr::bytes(self.fix.mux.prefix.clone()),
                Expr::bytes(self.fix.mux.suffix.clone()),
            ],
        );
        execute_input_with_covenants(tx, entries, 0).map_err(|err| OrchestratorError(format!("surrender failed: {err}")))?;
        self.game = Some(next);
        self.history.push(SubmittedTx {
            recipe_name: "route",
            consumed: vec![],
            produced: vec![],
            signer_names: vec![actor.name.clone()],
        });
        Ok(())
    }

    pub fn request_settlement(
        &mut self,
        requester: &SigningPlayer,
        opponent: &SigningPlayer,
        result: GameResult,
    ) -> Result<(), OrchestratorError> {
        self.require_registered(requester)?;
        self.require_registered(opponent)?;
        let game = self.game.as_ref().ok_or_else(|| OrchestratorError("missing game".to_string()))?;
        let requester_ref =
            requester.player_ref.as_ref().ok_or_else(|| OrchestratorError("requester missing player ref".to_string()))?;
        let opponent_ref = opponent.player_ref.as_ref().ok_or_else(|| OrchestratorError("opponent missing player ref".to_string()))?;
        let white_name = if requester_ref == &game.white_player {
            requester.name.clone()
        } else if opponent_ref == &game.white_player {
            opponent.name.clone()
        } else {
            return Err(OrchestratorError("missing white player in settlement request".to_string()));
        };
        let black_name = if requester_ref == &game.black_player {
            requester.name.clone()
        } else if opponent_ref == &game.black_player {
            opponent.name.clone()
        } else {
            return Err(OrchestratorError("missing black player in settlement request".to_string()));
        };
        for recipient in [white_name, black_name] {
            self.push_message(
                &recipient,
                OffchainMessage {
                    from: requester.name.clone(),
                    to: recipient.clone(),
                    kind: OffchainMessageKind::SettlementRequest { result },
                },
            );
        }
        Ok(())
    }

    pub fn settle_game(&mut self, white: &SigningPlayer, black: &SigningPlayer, result: GameResult) -> Result<(), OrchestratorError> {
        let game = self.game.clone().ok_or_else(|| OrchestratorError("missing game".to_string()))?;
        let expected_status = status_from_result(result);
        if game.status != expected_status {
            return Err(OrchestratorError(format!(
                "terminal game status {} does not match requested result {}",
                game.status, expected_status
            )));
        }
        let terminal = self.compile_mux(&game);
        let white_state = self.players.get(&white.name).cloned().ok_or_else(|| OrchestratorError("missing white".to_string()))?;
        let black_state = self.players.get(&black.name).cloned().ok_or_else(|| OrchestratorError("missing black".to_string()))?;
        let white_contract = self.compile_player(&white_state);
        let black_contract = self.compile_player(&black_state);

        let white_ref = white.player_ref.clone().ok_or_else(|| OrchestratorError("white missing player ref".to_string()))?;
        let black_ref = black.player_ref.clone().ok_or_else(|| OrchestratorError("black missing player ref".to_string()))?;
        let routed_settle = compile_settle_state(self.fix.settle.source, &self.player_hash, &white_ref, &black_ref, expected_status);
        let mux_settle_sigscript = entry_sigscript(
            &terminal,
            "settle",
            vec![
                Expr::bytes(self.player_hash.clone()),
                Expr::bytes(self.fix.settle.prefix.clone()),
                Expr::bytes(self.fix.settle.suffix.clone()),
            ],
        );
        let mux_tx = Transaction::new(
            1,
            vec![tx_input(0, mux_settle_sigscript, 0)],
            vec![covenant_output(&routed_settle, 0, self.covenant_id)],
            0,
            Default::default(),
            0,
            vec![],
        );
        execute_input_with_covenants(mux_tx, vec![covenant_utxo(&terminal, self.covenant_id)], 0)
            .map_err(|err| OrchestratorError(format!("mux settle failed: {err}")))?;

        let mut next_white = white_state.clone();
        let mut next_black = black_state.clone();
        if next_white.open_games <= 0 || next_black.open_games <= 0 {
            return Err(OrchestratorError("cannot settle players without open games".to_string()));
        }
        next_white.open_games -= 1;
        next_black.open_games -= 1;
        next_white.games += 1;
        next_black.games += 1;

        let (white_actual, black_actual) = match result {
            GameResult::WhiteWin => {
                next_white.wins += 1;
                next_black.losses += 1;
                (1000, 0)
            }
            GameResult::BlackWin => {
                next_white.losses += 1;
                next_black.wins += 1;
                (0, 1000)
            }
            GameResult::Draw => {
                next_white.draws += 1;
                next_black.draws += 1;
                (500, 500)
            }
        };

        let white_old_rating = next_white.rating;
        let black_old_rating = next_black.rating;
        next_white.rating = approx_updated_rating(white_old_rating, black_old_rating, white_actual);
        next_black.rating = approx_updated_rating(black_old_rating, white_old_rating, black_actual);

        let stake = 1_000u64;
        match result {
            GameResult::WhiteWin => {
                next_white.value += stake;
            }
            GameResult::BlackWin => {
                next_black.value += stake;
            }
            GameResult::Draw => {
                let white_share = stake / 2;
                let black_share = stake - white_share;
                next_white.value += white_share;
                next_black.value += black_share;
            }
        }

        let settled_white = self.compile_player(&next_white);
        let settled_black = self.compile_player(&next_black);
        let settle_sigscript = entry_sigscript(
            &routed_settle,
            "settle",
            vec![Expr::bytes(self.player_prefix.clone()), Expr::bytes(self.player_suffix.clone())],
        );

        let white_placeholder = entry_sigscript(
            &white_contract,
            "delegate_settle",
            vec![
                Expr::int(self.fix.settle.prefix.len() as i64),
                Expr::int(self.fix.settle.suffix.len() as i64),
                Expr::bytes(self.fix.settle.hash.clone()),
            ],
        );
        let black_placeholder = entry_sigscript(
            &black_contract,
            "delegate_settle",
            vec![
                Expr::int(self.fix.settle.prefix.len() as i64),
                Expr::int(self.fix.settle.suffix.len() as i64),
                Expr::bytes(self.fix.settle.hash.clone()),
            ],
        );
        let outputs = vec![
            covenant_output_with_value(&settled_white, 0, self.covenant_id, next_white.value),
            covenant_output_with_value(&settled_black, 0, self.covenant_id, next_black.value),
        ];
        let entries = vec![
            covenant_utxo(&routed_settle, self.covenant_id),
            covenant_utxo_with_value(&white_contract, self.covenant_id, white_state.value),
            covenant_utxo_with_value(&black_contract, self.covenant_id, black_state.value),
        ];
        let tx = Transaction::new(
            1,
            vec![tx_input(0, settle_sigscript, 0), tx_input(1, white_placeholder, 0), tx_input(2, black_placeholder, 0)],
            outputs,
            0,
            Default::default(),
            0,
            vec![],
        );
        execute_input_with_covenants(tx.clone(), entries.clone(), 0)
            .map_err(|err| OrchestratorError(format!("settle leader failed: {err}")))?;
        execute_input_with_covenants(tx.clone(), entries.clone(), 1)
            .map_err(|err| OrchestratorError(format!("settle white delegate failed: {err}")))?;
        execute_input_with_covenants(tx, entries, 2)
            .map_err(|err| OrchestratorError(format!("settle black delegate failed: {err}")))?;

        self.players.insert(white.name.clone(), next_white);
        self.players.insert(black.name.clone(), next_black);
        self.game = None;
        self.push_message(
            &white.name,
            OffchainMessage {
                from: "arena".to_string(),
                to: white.name.clone(),
                kind: OffchainMessageKind::SettlementNotice { result },
            },
        );
        self.push_message(
            &black.name,
            OffchainMessage {
                from: "arena".to_string(),
                to: black.name.clone(),
                kind: OffchainMessageKind::SettlementNotice { result },
            },
        );
        self.history.push(SubmittedTx { recipe_name: "mux_settle", consumed: vec![], produced: vec![], signer_names: vec![] });
        self.history.push(SubmittedTx { recipe_name: "settle", consumed: vec![], produced: vec![], signer_names: vec![] });
        Ok(())
    }

    pub fn retire_player(&mut self, player: &SigningPlayer) -> Result<(), OrchestratorError> {
        let state = self.players.get(&player.name).cloned().ok_or_else(|| OrchestratorError("missing player".to_string()))?;
        let contract = self.compile_player(&state);
        let placeholder =
            entry_sigscript(&contract, "retire", vec![Expr::bytes(vec![0u8; 65]), Expr::bytes(player.pubkey_bytes.clone())]);
        let entries = vec![covenant_utxo_with_value(&contract, self.covenant_id, state.value)];
        let mut tx = Transaction::new(1, vec![tx_input(0, placeholder, 1)], vec![], 0, Default::default(), 0, vec![]);
        let sig = sign_tx_input_schnorr(&tx, &entries, 0, player);
        tx.inputs[0].signature_script =
            entry_sigscript(&contract, "retire", vec![Expr::bytes(sig), Expr::bytes(player.pubkey_bytes.clone())]);
        execute_input_with_covenants(tx, entries, 0).map_err(|err| OrchestratorError(format!("retire failed: {err}")))?;
        self.players.remove(&player.name);
        self.history.push(SubmittedTx {
            recipe_name: "retire",
            consumed: vec![],
            produced: vec![],
            signer_names: vec![player.name.clone()],
        });
        Ok(())
    }

    fn planner(&self) -> ChessTxPlanner {
        ChessTxPlanner {
            family: ChessTemplateFamily {
                league: TemplateWitness { prefix: Vec::new(), suffix: Vec::new(), hash: self.league_hash.clone() },
                player: TemplateWitness {
                    prefix: self.player_prefix.clone(),
                    suffix: self.player_suffix.clone(),
                    hash: self.player_hash.clone(),
                },
                mux: TemplateWitness {
                    prefix: self.fix.mux.prefix.clone(),
                    suffix: self.fix.mux.suffix.clone(),
                    hash: self.fix.mux.hash.clone(),
                },
                settle: TemplateWitness {
                    prefix: self.fix.settle.prefix.clone(),
                    suffix: self.fix.settle.suffix.clone(),
                    hash: self.fix.settle.hash.clone(),
                },
                pawn: TemplateWitness {
                    prefix: self.fix.pawn.prefix.clone(),
                    suffix: self.fix.pawn.suffix.clone(),
                    hash: self.fix.pawn.hash.clone(),
                },
                knight: TemplateWitness {
                    prefix: self.fix.knight.prefix.clone(),
                    suffix: self.fix.knight.suffix.clone(),
                    hash: self.fix.knight.hash.clone(),
                },
                vert: TemplateWitness {
                    prefix: self.fix.vert.prefix.clone(),
                    suffix: self.fix.vert.suffix.clone(),
                    hash: self.fix.vert.hash.clone(),
                },
                horiz: TemplateWitness {
                    prefix: self.fix.horiz.prefix.clone(),
                    suffix: self.fix.horiz.suffix.clone(),
                    hash: self.fix.horiz.hash.clone(),
                },
                diag: TemplateWitness {
                    prefix: self.fix.diag.prefix.clone(),
                    suffix: self.fix.diag.suffix.clone(),
                    hash: self.fix.diag.hash.clone(),
                },
                king: TemplateWitness {
                    prefix: self.fix.king.prefix.clone(),
                    suffix: self.fix.king.suffix.clone(),
                    hash: self.fix.king.hash.clone(),
                },
                castle: TemplateWitness {
                    prefix: self.fix.castle.prefix.clone(),
                    suffix: self.fix.castle.suffix.clone(),
                    hash: self.fix.castle.hash.clone(),
                },
                castle_challenge: TemplateWitness {
                    prefix: self.fix.castle_challenge.prefix.clone(),
                    suffix: self.fix.castle_challenge.suffix.clone(),
                    hash: self.fix.castle_challenge.hash.clone(),
                },
                route_hashes: packed_execution_route_hashes(&self.fix),
                routes_commitment: routes_commitment(&packed_execution_route_hashes(&self.fix)),
            },
        }
    }

    fn push_message(&mut self, recipient: &str, message: OffchainMessage) {
        self.messages.entry(recipient.to_string()).or_default().push(message);
    }

    fn require_registered(&self, player: &SigningPlayer) -> Result<(), OrchestratorError> {
        if player.player_ref.is_none() || player.player_id.is_none() {
            return Err(OrchestratorError(format!("{} is not registered", player.name)));
        }
        Ok(())
    }

    fn player_account(&self, player_ref: &[u8]) -> Result<PlayerAccount, OrchestratorError> {
        self.players
            .iter()
            .find_map(|(name, state)| {
                (blake2b([state.owner_hash.as_slice(), state.player_id.as_slice()].concat().as_slice()) == player_ref).then_some(
                    PlayerAccount {
                        owner_name: name.clone(),
                        owner_hash: state.owner_hash.clone(),
                        player_id: state.player_id.clone(),
                        player_ref: player_ref.to_vec(),
                        value: state.value,
                        open_games: state.open_games,
                        rating: state.rating,
                        games: state.games,
                        wins: state.wins,
                        draws: state.draws,
                        losses: state.losses,
                    },
                )
            })
            .ok_or_else(|| OrchestratorError("missing player account".to_string()))
    }

    fn compile_player(&self, state: &PlayerStateData) -> CompiledContract<'static> {
        compile_player_state(
            player_static_source(),
            PlayerStateArgs {
                league_hash: &self.league_hash,
                player_hash: &self.player_hash,
                mux_hash: &self.fix.mux.hash,
                routes_commitment: &routes_commitment(&packed_execution_route_hashes(&self.fix)),
                owner_hash: &state.owner_hash,
                player_id: &state.player_id,
                open_games: state.open_games,
                rating: state.rating,
                games: state.games,
                wins: state.wins,
                draws: state.draws,
                losses: state.losses,
            },
        )
    }

    fn compile_mux(&self, state: &GameStateData) -> CompiledContract<'static> {
        compile_game_state(self.fix.mux.source, &self.fix, state)
    }

    fn compile_worker(&self, source: &'static str, state: &GameStateData) -> CompiledContract<'static> {
        compile_game_state(source, &self.fix, state)
    }

    fn worker_fixture(&self, worker: WorkerKind) -> &TemplateFixture {
        match worker {
            WorkerKind::Pawn => &self.fix.pawn,
            WorkerKind::Knight => &self.fix.knight,
            WorkerKind::Vert => &self.fix.vert,
            WorkerKind::Horiz => &self.fix.horiz,
            WorkerKind::Diag => &self.fix.diag,
            WorkerKind::King => &self.fix.king,
            WorkerKind::Castle => &self.fix.castle,
            WorkerKind::CastleChallenge => &self.fix.castle_challenge,
        }
    }
}

fn build_execution_fixture() -> ExecutionFixture {
    let mux_source = load_static_contract_source(mux_contract_path());
    let settle_source = load_static_contract_source(settle_contract_path());
    let pawn_source = load_static_contract_source(pawn_contract_path());
    let knight_source = load_static_contract_source(knight_contract_path());
    let vert_source = load_static_contract_source(vert_contract_path());
    let horiz_source = load_static_contract_source(horiz_contract_path());
    let diag_source = load_static_contract_source(diag_contract_path());
    let king_source = load_static_contract_source(king_contract_path());
    let castle_source = load_static_contract_source(castle_contract_path());
    let castle_challenge_source = load_static_contract_source(castle_challenge_contract_path());
    let dummy_board = standard_board();
    let game_ctor = vec![
        Expr::bytes(vec![0x11u8; 32]),
        Expr::bytes(vec![0x33u8; 32 * 9]),
        Expr::bytes(vec![0x21u8; 32]),
        Expr::bytes(vec![0x22u8; 32]),
        Expr::bytes(dummy_board),
        Expr::int(0),
        Expr::int(0),
        Expr::int(DEFAULT_MOVE_TIMEOUT),
        Expr::bytes(vec![1u8; 4]),
        Expr::int(-1),
        Expr::int(-1),
        Expr::int(-1),
        Expr::int(0),
        Expr::int(0),
        Expr::int(3),
    ];
    let settle_ctor = vec![Expr::bytes(vec![0x44u8; 32]), Expr::bytes(vec![0x21u8; 32]), Expr::bytes(vec![0x22u8; 32]), Expr::int(0)];
    ExecutionFixture {
        mux: template_fixture(mux_source, &game_ctor),
        settle: template_fixture(settle_source, &settle_ctor),
        pawn: template_fixture(pawn_source, &game_ctor),
        knight: template_fixture(knight_source, &game_ctor),
        vert: template_fixture(vert_source, &game_ctor),
        horiz: template_fixture(horiz_source, &game_ctor),
        diag: template_fixture(diag_source, &game_ctor),
        king: template_fixture(king_source, &game_ctor),
        castle: template_fixture(castle_source, &game_ctor),
        castle_challenge: template_fixture(castle_challenge_source, &game_ctor),
    }
}

fn load_static_contract_source(path: &'static str) -> &'static str {
    Box::leak(load_contract_source(path).into_boxed_str())
}

fn league_static_source() -> &'static str {
    load_static_contract_source(league_contract_path())
}

fn player_static_source() -> &'static str {
    load_static_contract_source(player_contract_path())
}

fn template_fixture(source: &'static str, ctor: &[Expr<'_>]) -> TemplateFixture {
    let compiled = compile_contract(source, ctor, CompileOptions::default()).expect("compile template source succeeds");
    let layout = compiled.state_layout;
    let prefix = compiled.script[..layout.start].to_vec();
    let suffix = compiled.script[layout.start + layout.len..].to_vec();
    let hash = blake2b([prefix.as_slice(), suffix.as_slice()].concat().as_slice());
    TemplateFixture { source, prefix, suffix, hash }
}

fn packed_execution_route_hashes(fix: &ExecutionFixture) -> Vec<u8> {
    let player_hash = {
        let player_template = compile_player_state(
            player_static_source(),
            PlayerStateArgs {
                league_hash: &[0x11u8; 32],
                player_hash: &[0x22u8; 32],
                mux_hash: &fix.mux.hash,
                routes_commitment: &routes_commitment(&vec![0x12u8; 32 * 9]),
                owner_hash: &[0x44u8; 32],
                player_id: &[0x55u8; 32],
                open_games: 0,
                rating: 1200,
                games: 0,
                wins: 0,
                draws: 0,
                losses: 0,
            },
        );
        let layout = player_template.state_layout;
        blake2b(
            [player_template.script[..layout.start].as_ref(), player_template.script[layout.start + layout.len..].as_ref()]
                .concat()
                .as_slice(),
        )
    };
    let mut out = Vec::with_capacity(32 * 9);
    out.extend_from_slice(&fix.pawn.hash);
    out.extend_from_slice(&fix.knight.hash);
    out.extend_from_slice(&fix.vert.hash);
    out.extend_from_slice(&fix.horiz.hash);
    out.extend_from_slice(&fix.diag.hash);
    out.extend_from_slice(&fix.king.hash);
    out.extend_from_slice(&fix.castle.hash);
    out.extend_from_slice(&fix.castle_challenge.hash);
    out.extend_from_slice(&blake2b([fix.settle.hash.as_slice(), player_hash.as_slice()].concat().as_slice()));
    out
}

fn routes_commitment(route_hashes: &[u8]) -> Vec<u8> {
    blake2b(route_hashes)
}

fn square_idx(x: i64, y: i64) -> i64 {
    y * 8 + x
}

fn move_piece(board: &mut [u8], from_x: usize, from_y: usize, to_x: usize, to_y: usize) {
    let from_idx = from_y * 8 + from_x;
    let to_idx = to_y * 8 + to_x;
    let piece = board[from_idx];
    board[from_idx] = 0;
    board[to_idx] = piece;
}

fn worker_selector(worker: WorkerKind) -> i64 {
    match worker {
        WorkerKind::Pawn => 0,
        WorkerKind::Knight => 1,
        WorkerKind::Vert => 2,
        WorkerKind::Horiz => 3,
        WorkerKind::Diag => 4,
        WorkerKind::King => 5,
        WorkerKind::Castle => 6,
        WorkerKind::CastleChallenge => 7,
    }
}

fn side_from_turn(turn: i64) -> Side {
    if turn == 0 {
        Side::White
    } else {
        Side::Black
    }
}

fn status_from_result(result: GameResult) -> i64 {
    match result {
        GameResult::WhiteWin => 1,
        GameResult::BlackWin => 2,
        GameResult::Draw => 3,
    }
}

fn determine_worker(board: &[u8], mv: MoveSpec) -> Result<WorkerKind, OrchestratorError> {
    if !(0..8).contains(&mv.from_x) || !(0..8).contains(&mv.from_y) || !(0..8).contains(&mv.to_x) || !(0..8).contains(&mv.to_y) {
        return Err(OrchestratorError("move coordinates must stay on board".to_string()));
    }
    let piece = board[square_idx(mv.from_x, mv.from_y) as usize];
    if piece == 0 {
        return Err(OrchestratorError("no piece on source square".to_string()));
    }
    let base = if piece > 8 { piece - 8 } else { piece };
    let dx = mv.to_x - mv.from_x;
    let dy = mv.to_y - mv.from_y;
    match base {
        1 => Ok(WorkerKind::Pawn),
        2 => Ok(WorkerKind::Knight),
        3 => Ok(WorkerKind::Diag),
        4 => {
            if dx == 0 {
                Ok(WorkerKind::Vert)
            } else if dy == 0 {
                Ok(WorkerKind::Horiz)
            } else {
                Err(OrchestratorError("rook move must stay on file or rank".to_string()))
            }
        }
        5 => {
            if dx == 0 {
                Ok(WorkerKind::Vert)
            } else if dy == 0 {
                Ok(WorkerKind::Horiz)
            } else if dx.abs() == dy.abs() {
                Ok(WorkerKind::Diag)
            } else {
                Err(OrchestratorError("queen move must be straight or diagonal".to_string()))
            }
        }
        6 => {
            if dy == 0 && dx.abs() == 2 {
                Ok(WorkerKind::Castle)
            } else {
                Ok(WorkerKind::King)
            }
        }
        _ => Err(OrchestratorError("unknown piece kind".to_string())),
    }
}

fn pending_state_for_move(game: &GameStateData, mv: MoveSpec) -> GameStateData {
    GameStateData {
        white_player: game.white_player.clone(),
        black_player: game.black_player.clone(),
        board: game.board.clone(),
        turn: game.turn,
        status: game.status,
        move_timeout: game.move_timeout,
        castle_rights: game.castle_rights,
        en_passant_idx: game.en_passant_idx,
        pending_src_idx: square_idx(mv.from_x, mv.from_y),
        pending_dst_idx: square_idx(mv.to_x, mv.to_y),
        pending_promo: mv.promo_piece,
        recent_castle: 0,
        draw_state: game.draw_state,
        move_log: game.move_log.clone(),
    }
}

fn clear_castle_rights_for_square(castle_rights: &mut [u8; 4], x: i64, y: i64) {
    match (x, y) {
        (7, 0) => castle_rights[0] = 0,
        (0, 0) => castle_rights[1] = 0,
        (7, 7) => castle_rights[2] = 0,
        (0, 7) => castle_rights[3] = 0,
        _ => {}
    }
}

fn apply_move_to_state(game: &GameStateData, mv: MoveSpec) -> Result<GameStateData, OrchestratorError> {
    let mut board = game.board.clone();
    let from_idx = square_idx(mv.from_x, mv.from_y) as usize;
    let to_idx = square_idx(mv.to_x, mv.to_y) as usize;
    let piece = board[from_idx];
    if piece == 0 {
        return Err(OrchestratorError("no piece on source square".to_string()));
    }
    let base = if piece > 8 { piece - 8 } else { piece };
    let is_black = piece > 8;
    let mut castle_rights = game.castle_rights;
    let mut en_passant_idx = -1;
    let mut recent_castle = 0;

    clear_castle_rights_for_square(&mut castle_rights, mv.to_x, mv.to_y);
    if base == 6 {
        if is_black {
            castle_rights[2] = 0;
            castle_rights[3] = 0;
        } else {
            castle_rights[0] = 0;
            castle_rights[1] = 0;
        }
    }
    if base == 4 {
        clear_castle_rights_for_square(&mut castle_rights, mv.from_x, mv.from_y);
    }

    if base == 1 {
        let direction = if is_black { -1 } else { 1 };
        if mv.from_x != mv.to_x && board[to_idx] == 0 && game.en_passant_idx == square_idx(mv.to_x, mv.to_y) {
            let captured_y = mv.to_y - direction;
            board[square_idx(mv.to_x, captured_y) as usize] = 0;
        }
        board[from_idx] = 0;
        let mut placed_piece = piece;
        if mv.promo_piece != 0 {
            placed_piece = if is_black { (mv.promo_piece as u8) + 8 } else { mv.promo_piece as u8 };
        }
        board[to_idx] = placed_piece;
        if mv.from_x == mv.to_x && (mv.to_y - mv.from_y).abs() == 2 {
            en_passant_idx = square_idx(mv.from_x, mv.from_y + direction);
        }
    } else if base == 6 && (mv.to_x - mv.from_x).abs() == 2 && mv.from_y == mv.to_y {
        board[from_idx] = 0;
        board[to_idx] = piece;
        if mv.to_x > mv.from_x {
            move_piece(&mut board, 7, mv.from_y as usize, 5, mv.from_y as usize);
            recent_castle = if is_black { 3 } else { 1 };
        } else {
            move_piece(&mut board, 0, mv.from_y as usize, 3, mv.from_y as usize);
            recent_castle = if is_black { 4 } else { 2 };
        }
    } else {
        move_piece(&mut board, mv.from_x as usize, mv.from_y as usize, mv.to_x as usize, mv.to_y as usize);
    }

    let mut move_log = game.move_log.clone();
    move_log.push(mv.label());
    Ok(GameStateData {
        white_player: game.white_player.clone(),
        black_player: game.black_player.clone(),
        board,
        turn: 1 - game.turn,
        status: game.status,
        move_timeout: game.move_timeout,
        castle_rights,
        en_passant_idx,
        pending_src_idx: -1,
        pending_dst_idx: -1,
        pending_promo: 0,
        recent_castle,
        draw_state: game.draw_state,
        move_log,
    })
}

fn compile_game_state(source: &'static str, fix: &ExecutionFixture, state: &GameStateData) -> CompiledContract<'static> {
    let ctor = vec![
        Expr::bytes(fix.mux.hash.clone()),
        Expr::bytes(packed_execution_route_hashes(fix)),
        Expr::bytes(state.white_player.clone()),
        Expr::bytes(state.black_player.clone()),
        Expr::bytes(state.board.clone()),
        Expr::int(state.turn),
        Expr::int(state.status),
        Expr::int(state.move_timeout),
        Expr::bytes(state.castle_rights.to_vec()),
        Expr::int(state.en_passant_idx),
        Expr::int(state.pending_src_idx),
        Expr::int(state.pending_dst_idx),
        Expr::int(state.pending_promo),
        Expr::int(state.recent_castle),
        Expr::int(state.draw_state),
    ];
    compile_contract(source, &ctor, CompileOptions::default()).expect("compile game state")
}

fn compile_player_state(source: &'static str, args: PlayerStateArgs<'_>) -> CompiledContract<'static> {
    let ctor = vec![
        Expr::bytes(args.league_hash.to_vec()),
        Expr::bytes(args.player_hash.to_vec()),
        Expr::bytes(args.mux_hash.to_vec()),
        Expr::bytes(args.routes_commitment.to_vec()),
        Expr::bytes(args.owner_hash.to_vec()),
        Expr::bytes(args.player_id.to_vec()),
        Expr::int(args.open_games),
        Expr::int(args.rating),
        Expr::int(args.games),
        Expr::int(args.wins),
        Expr::int(args.draws),
        Expr::int(args.losses),
    ];
    compile_contract(source, &ctor, CompileOptions::default()).expect("compile player state")
}

fn compile_league_state(
    source: &'static str,
    league_hash: &[u8],
    player_hash: &[u8],
    mux_hash: &[u8],
    routes_commitment: &[u8],
    base_rating: i64,
    admin: &[u8],
) -> CompiledContract<'static> {
    let ctor = vec![
        Expr::bytes(league_hash.to_vec()),
        Expr::bytes(player_hash.to_vec()),
        Expr::bytes(mux_hash.to_vec()),
        Expr::bytes(routes_commitment.to_vec()),
        Expr::int(base_rating),
        Expr::bytes(admin.to_vec()),
    ];
    compile_contract(source, &ctor, CompileOptions::default()).expect("compile league state")
}

fn compile_settle_state(
    source: &'static str,
    player_hash: &[u8],
    white_hash: &[u8],
    black_hash: &[u8],
    status: i64,
) -> CompiledContract<'static> {
    let ctor =
        vec![Expr::bytes(player_hash.to_vec()), Expr::bytes(white_hash.to_vec()), Expr::bytes(black_hash.to_vec()), Expr::int(status)];
    compile_contract(source, &ctor, CompileOptions::default()).expect("compile settle state")
}

fn entry_sigscript(compiled: &CompiledContract<'_>, function: &str, args: Vec<Expr<'_>>) -> Vec<u8> {
    let sigscript = compiled.build_sig_script(function, args).expect("sigscript builds");
    pay_to_script_hash_signature_script(compiled.script.clone(), sigscript).expect("wrap p2sh sigscript")
}

fn tx_input(index: u32, signature_script: Vec<u8>, sig_op_count: u8) -> TransactionInput {
    TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([index as u8 + 1; 32]), index },
        signature_script,
        sequence: 0,
        sig_op_count,
    }
}

fn covenant_output_with_value(
    compiled: &CompiledContract<'_>,
    authorizing_input: u16,
    covenant_id: Hash,
    value: u64,
) -> TransactionOutput {
    TransactionOutput {
        value,
        script_public_key: pay_to_script_hash_script(&compiled.script),
        covenant: Some(CovenantBinding { authorizing_input, covenant_id }),
    }
}

fn covenant_output(compiled: &CompiledContract<'_>, authorizing_input: u16, covenant_id: Hash) -> TransactionOutput {
    covenant_output_with_value(compiled, authorizing_input, covenant_id, 1_000)
}

fn covenant_utxo_with_value(compiled: &CompiledContract<'_>, covenant_id: Hash, value: u64) -> UtxoEntry {
    UtxoEntry::new(value, pay_to_script_hash_script(&compiled.script), 0, false, Some(covenant_id))
}

fn covenant_utxo(compiled: &CompiledContract<'_>, covenant_id: Hash) -> UtxoEntry {
    covenant_utxo_with_value(compiled, covenant_id, 1_000)
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
    let populated = PopulatedTransaction::new(&tx, vec![UtxoEntry::new(1_000, Default::default(), 0, false, None)]);
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

fn sign_tx_input_schnorr(tx: &Transaction, entries: &[UtxoEntry], input_idx: usize, player: &SigningPlayer) -> Vec<u8> {
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

fn load_template_family() -> Result<ChessTemplateFamily, OrchestratorError> {
    let mux = compile_template(mux_contract_path(), &mux_constructor_args())?;
    let player = compile_template(player_contract_path(), &player_constructor_args(&mux.hash, &sample_routes_commitment()))?;
    let settle = compile_template(settle_contract_path(), &settle_constructor_args(&player.hash))?;
    let pawn = compile_template(pawn_contract_path(), &worker_constructor_args(&mux.hash))?;
    let knight = compile_template(knight_contract_path(), &worker_constructor_args(&mux.hash))?;
    let vert = compile_template(vert_contract_path(), &worker_constructor_args(&mux.hash))?;
    let horiz = compile_template(horiz_contract_path(), &worker_constructor_args(&mux.hash))?;
    let diag = compile_template(diag_contract_path(), &worker_constructor_args(&mux.hash))?;
    let king = compile_template(king_contract_path(), &worker_constructor_args(&mux.hash))?;
    let castle = compile_template(castle_contract_path(), &worker_constructor_args(&mux.hash))?;
    let castle_challenge = compile_template(castle_challenge_contract_path(), &worker_constructor_args(&mux.hash))?;

    let route_hashes =
        packed_route_hashes(&player.hash, &settle.hash, [&pawn, &knight, &vert, &horiz, &diag, &king, &castle, &castle_challenge]);
    let routes_commitment = blake2b(&route_hashes);
    let league = compile_template(league_contract_path(), &league_constructor_args(&player.hash, &mux.hash, &routes_commitment))?;

    Ok(ChessTemplateFamily {
        league,
        player,
        mux,
        settle,
        pawn,
        knight,
        vert,
        horiz,
        diag,
        king,
        castle,
        castle_challenge,
        route_hashes,
        routes_commitment,
    })
}

fn compile_template(path: &str, args: &[Expr<'static>]) -> Result<TemplateWitness, OrchestratorError> {
    let source = load_contract_source(path);
    let compiled = compile_contract(&source, args, CompileOptions::default())
        .map_err(|err| OrchestratorError(format!("failed to compile {path}: {err}")))?;
    let layout = compiled.state_layout;
    let prefix = compiled.script[..layout.start].to_vec();
    let suffix = compiled.script[layout.start + layout.len..].to_vec();
    let hash = blake2b([prefix.as_slice(), suffix.as_slice()].concat().as_slice());
    Ok(TemplateWitness { prefix, suffix, hash })
}

fn blake2b(data: &[u8]) -> Vec<u8> {
    Blake2bParams::new().hash_length(32).to_state().update(data).finalize().as_bytes().to_vec()
}

fn derive_player_id(nonce: u32, owner_hash: &[u8]) -> Vec<u8> {
    blake2b([b"LeaguePlayerId".as_slice(), &nonce.to_le_bytes(), owner_hash].concat().as_slice())
}

fn file_char(x: i64) -> char {
    (b'a' + (x as u8)) as char
}

fn rank_char(y: i64) -> char {
    (b'1' + (y as u8)) as char
}

fn standard_board() -> Vec<u8> {
    vec![
        0x04, 0x02, 0x03, 0x05, 0x06, 0x03, 0x02, 0x04, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x0c, 0x0a, 0x0b, 0x0d, 0x0e, 0x0b, 0x0a,
        0x0c,
    ]
}

fn sample_route_hashes() -> Vec<u8> {
    let mut route_hashes = Vec::with_capacity(32 * 9);
    for byte in 0x12u8..=0x1au8 {
        route_hashes.extend_from_slice(&[byte; 32]);
    }
    route_hashes
}

fn sample_routes_commitment() -> Vec<u8> {
    blake2b(&sample_route_hashes())
}

fn worker_constructor_args(mux_hash: &[u8]) -> Vec<Expr<'static>> {
    vec![
        Expr::bytes(mux_hash.to_vec()),
        Expr::bytes(sample_route_hashes()),
        Expr::bytes(vec![0x21u8; 32]),
        Expr::bytes(vec![0x22u8; 32]),
        Expr::bytes(standard_board()),
        Expr::int(0),
        Expr::int(0),
        Expr::int(DEFAULT_MOVE_TIMEOUT),
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
    vec![
        Expr::bytes(vec![0x11u8; 32]),
        Expr::bytes(sample_route_hashes()),
        Expr::bytes(vec![0x21u8; 32]),
        Expr::bytes(vec![0x22u8; 32]),
        Expr::bytes(vec![0u8; 64]),
        Expr::int(0),
        Expr::int(0),
        Expr::int(DEFAULT_MOVE_TIMEOUT),
        Expr::bytes(vec![1u8; 4]),
        Expr::int(-1),
        Expr::int(-1),
        Expr::int(-1),
        Expr::int(0),
        Expr::int(0),
        Expr::int(3),
    ]
}

fn player_constructor_args(mux_hash: &[u8], routes_commitment: &[u8]) -> Vec<Expr<'static>> {
    vec![
        Expr::bytes(vec![0x11u8; 32]),
        Expr::bytes(vec![0x22u8; 32]),
        Expr::bytes(mux_hash.to_vec()),
        Expr::bytes(routes_commitment.to_vec()),
        Expr::bytes(vec![0x44u8; 32]),
        Expr::bytes(vec![0x55u8; 32]),
        Expr::int(0),
        Expr::int(1200),
        Expr::int(7),
        Expr::int(4),
        Expr::int(2),
        Expr::int(1),
    ]
}

fn league_constructor_args(player_hash: &[u8], mux_hash: &[u8], routes_commitment: &[u8]) -> Vec<Expr<'static>> {
    vec![
        Expr::bytes(vec![0x11u8; 32]),
        Expr::bytes(player_hash.to_vec()),
        Expr::bytes(mux_hash.to_vec()),
        Expr::bytes(routes_commitment.to_vec()),
        Expr::int(1200),
        Expr::bytes(vec![0x44u8; 32]),
    ]
}

fn settle_constructor_args(player_hash: &[u8]) -> Vec<Expr<'static>> {
    vec![Expr::bytes(player_hash.to_vec()), Expr::bytes(vec![0x21u8; 32]), Expr::bytes(vec![0x22u8; 32]), Expr::int(1)]
}

fn packed_route_hashes(player_hash: &[u8], settle_hash: &[u8], workers: [&TemplateWitness; 8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 * 9);
    for worker in workers {
        out.extend_from_slice(&worker.hash);
    }
    let settle_commitment = blake2b([settle_hash, player_hash].concat().as_slice());
    out.extend_from_slice(&settle_commitment);
    out
}

fn approx_expected_score(diff: i64) -> i64 {
    let abs_diff = diff.abs();
    let favored_expected = if abs_diff < 75 {
        500
    } else if abs_diff < 150 {
        600
    } else if abs_diff < 250 {
        700
    } else if abs_diff < 400 {
        820
    } else if abs_diff < 600 {
        910
    } else if abs_diff < 800 {
        970
    } else {
        990
    };

    if diff < 0 {
        favored_expected
    } else if diff > 0 {
        1000 - favored_expected
    } else {
        500
    }
}

fn approx_updated_rating(self_rating: i64, opp_rating: i64, actual_score: i64) -> i64 {
    let expected = approx_expected_score(opp_rating - self_rating);
    self_rating + ((32 * (actual_score - expected)) / 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_template_family_with_real_route_commitment() {
        let planner = ChessTxPlanner::load().expect("template family loads");
        assert_eq!(planner.family.route_hashes.len(), 32 * 9);
        assert_eq!(planner.family.routes_commitment.len(), 32);
    }

    #[test]
    fn settlement_recipe_uses_unsigned_player_delegates() {
        let planner = ChessTxPlanner::load().expect("template family loads");
        let white_win = planner.settlement_recipe(GameResult::WhiteWin);
        assert_eq!(white_win.settle_step.calls[1].signer, SignerRequirement::None);
        assert_eq!(white_win.settle_step.calls[2].signer, SignerRequirement::None);

        let draw = planner.settlement_recipe(GameResult::Draw);
        assert_eq!(draw.settle_step.calls[1].signer, SignerRequirement::None);
        assert_eq!(draw.settle_step.calls[2].signer, SignerRequirement::None);
    }

    #[test]
    fn local_orchestrators_can_play_settle_and_retire_end_to_end() {
        let planner = ChessTxPlanner::load().expect("planner loads");
        let mut arena = LocalArena::new(planner);
        let mut white = PlayerHandle::new("white", 0x21);
        let mut black = PlayerHandle::new("black", 0x22);

        let reg_white = arena.register_player(&mut white).expect("white registers");
        let reg_black = arena.register_player(&mut black).expect("black registers");
        assert_eq!(reg_white.recipe_name, "register_player");
        assert_eq!(reg_black.recipe_name, "register_player");

        arena.send_game_invite(&white, &black).expect("invite sends");
        let black_mail = arena.drain_inbox(&black);
        assert_eq!(black_mail.len(), 1);
        assert!(matches!(black_mail[0].kind, OffchainMessageKind::GameInvite { .. }));

        let start = arena.start_game(&white, &black).expect("game starts");
        assert_eq!(start.recipe_name, "start_game");
        let game = arena.active_game_snapshot().expect("active game exists");
        assert_eq!(game.turn, Side::White);

        let white_move = arena.submit_move(&white, WorkerKind::Pawn, "e2e4").expect("white move succeeds");
        assert_eq!(white_move.len(), 2);
        let black_move_notice = arena.drain_inbox(&black);
        assert_eq!(black_move_notice.len(), 1);
        assert!(matches!(black_move_notice[0].kind, OffchainMessageKind::MoveNotice { .. }));
        let game = arena.active_game_snapshot().expect("active game exists");
        assert_eq!(game.turn, Side::Black);

        let settle = arena.settle_game(&white, &black, GameResult::WhiteWin).expect("settlement succeeds");
        assert_eq!(settle.len(), 2);
        let white_state = arena.player_account_snapshot(&white).expect("white state exists");
        let black_state = arena.player_account_snapshot(&black).expect("black state exists");
        assert_eq!(white_state.open_games, 0);
        assert_eq!(black_state.open_games, 0);
        assert_eq!(white_state.games, 1);
        assert_eq!(black_state.games, 1);
        assert_eq!(white_state.wins, 1);
        assert_eq!(black_state.losses, 1);
        assert_eq!(white_state.value, 2_000);
        assert_eq!(black_state.value, 1_000);
        assert!(white_state.rating > 1200);
        assert!(black_state.rating < 1200);

        let retire = arena.retire_player(&white).expect("white retires");
        assert_eq!(retire.recipe_name, "retire");
        assert!(arena.player_account_snapshot(&white).is_err());
        assert_eq!(arena.history().len(), 8);
    }

    #[test]
    fn actual_txs_can_play_a_short_game_end_to_end() {
        let shared = TxArena::shared().expect("actual arena builds");
        let mut white = TxOrchestrator::new("white", 0x31, shared.clone());
        let mut black = TxOrchestrator::new("black", 0x32, shared.clone());

        white.register().expect("white register tx passes");
        black.register().expect("black register tx passes");

        white.send_game_invite(&black).expect("white sends invite");
        let invite_mail = black.inbox();
        assert!(matches!(invite_mail.as_slice(), [OffchainMessage { kind: OffchainMessageKind::GameInvite { .. }, .. }]));

        black.accept_game_invite(&white).expect("black accepts invite");
        let accepted_mail = white.inbox();
        assert!(matches!(accepted_mail.as_slice(), [OffchainMessage { kind: OffchainMessageKind::InviteAccepted { .. }, .. }]));

        white.start_game(&black).expect("start game tx passes");
        let started_mail_white = white.inbox();
        let started_mail = black.inbox();
        assert!(matches!(started_mail_white.as_slice(), [OffchainMessage { kind: OffchainMessageKind::GameStarted { .. }, .. }]));
        assert!(matches!(started_mail.as_slice(), [OffchainMessage { kind: OffchainMessageKind::GameStarted { .. }, .. }]));

        white.submit_move(MoveSpec::new(4, 1, 4, 3)).expect("white e2e4 txs pass");
        let move_mail = black.inbox();
        assert!(matches!(
            move_mail.as_slice(),
            [OffchainMessage { kind: OffchainMessageKind::MoveNotice { ref move_label, .. }, .. }] if move_label == "e2e4"
        ));

        black.submit_move(MoveSpec::new(6, 7, 5, 5)).expect("black g8f6 txs pass");
        let reply_mail = white.inbox();
        assert!(matches!(
            reply_mail.as_slice(),
            [OffchainMessage { kind: OffchainMessageKind::MoveNotice { ref move_label, .. }, .. }] if move_label == "g8f6"
        ));

        white.submit_move(MoveSpec::new(5, 0, 2, 3)).expect("white bishop f1c4 txs pass");
        black.inbox();

        black.surrender().expect("black surrender tx passes");
        black.request_settlement(&white, GameResult::WhiteWin).expect("black requests settlement");
        let settlement_request = white.inbox();
        assert!(matches!(
            settlement_request.as_slice(),
            [OffchainMessage { kind: OffchainMessageKind::SettlementRequest { result: GameResult::WhiteWin, .. }, .. }]
        ));

        white.settle(&black, GameResult::WhiteWin).expect("settlement txs pass");
        let settlement_notice = black.inbox();
        assert!(settlement_notice
            .iter()
            .any(|message| { matches!(message.kind, OffchainMessageKind::SettlementNotice { result: GameResult::WhiteWin }) }));

        {
            let arena = shared.borrow();
            let white_state = arena.player_account_snapshot(&white.player).expect("white player remains after settlement");
            let black_state = arena.player_account_snapshot(&black.player).expect("black player remains after settlement");
            assert_eq!(white_state.value, 2_000);
            assert_eq!(black_state.value, 1_000);
        }

        white.retire().expect("retire tx passes");

        let arena = shared.borrow();
        let game = arena.active_game_snapshot();
        assert!(game.is_none());
        let white_state = arena.player_account_snapshot(&white.player);
        let black_state = arena.player_account_snapshot(&black.player).expect("black player remains");
        assert!(white_state.is_err());
        assert_eq!(black_state.open_games, 0);
        assert_eq!(black_state.losses, 1);
        assert_eq!(arena.history().len(), 13);
    }
}
