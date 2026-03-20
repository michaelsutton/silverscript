use std::collections::BTreeMap;

use blake2b_simd::Params as Blake2bParams;
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, CompileOptions};

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
    WhiteIfEntitled,
    BlackIfEntitled,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlayerAccount {
    pub owner_name: String,
    pub owner_hash: Vec<u8>,
    pub player_id: Vec<u8>,
    pub player_ref: Vec<u8>,
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
    MoveNotice { actor: String, worker: WorkerKind, move_label: String },
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
            outputs: vec![PlannedOutput { role: ContractRole::Mux, count: 1 }],
        }
    }

    pub fn worker_timeout_recipe(&self, worker: WorkerKind) -> TxRecipe {
        TxRecipe {
            name: "worker_timeout",
            calls: vec![PlannedCall { role: ContractRole::Worker(worker), function: "timeout", signer: SignerRequirement::None }],
            outputs: vec![PlannedOutput { role: ContractRole::Mux, count: 1 }],
        }
    }

    pub fn settlement_recipe(&self, result: GameResult) -> SettlementRecipe {
        let (white_signer, black_signer) = match result {
            GameResult::WhiteWin => (SignerRequirement::WhiteIfEntitled, SignerRequirement::None),
            GameResult::BlackWin => (SignerRequirement::None, SignerRequirement::BlackIfEntitled),
            GameResult::Draw => (SignerRequirement::WhiteIfEntitled, SignerRequirement::BlackIfEntitled),
        };

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
                    PlannedCall { role: ContractRole::Player, function: "delegate_settle", signer: white_signer },
                    PlannedCall { role: ContractRole::Player, function: "delegate_settle", signer: black_signer },
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
                kind: OffchainMessageKind::MoveNotice { actor: actor.name.clone(), worker, move_label },
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

        self.utxos.remove(&settle_id);
        self.utxos.remove(&white_player_id);
        self.utxos.remove(&black_player_id);

        let next_white_id = self.alloc_utxo(LocalUtxo::Player(white_account));
        let next_black_id = self.alloc_utxo(LocalUtxo::Player(black_account));

        let signers = match result {
            GameResult::WhiteWin => vec![white.name.clone()],
            GameResult::BlackWin => vec![black.name.clone()],
            GameResult::Draw => vec![white.name.clone(), black.name.clone()],
        };
        let settle_tx = SubmittedTx {
            recipe_name: self.planner.settlement_recipe(result).settle_step.name,
            consumed: vec![settle_id, white_player_id, black_player_id],
            produced: vec![next_white_id, next_black_id],
            signer_names: signers,
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
    use std::cell::RefCell;
    use std::rc::Rc;

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
    use silverscript_lang::compiler::CompiledContract;

    #[derive(Clone)]
    struct KeyedPlayer {
        name: String,
        keypair: Keypair,
        pubkey_bytes: Vec<u8>,
        owner_hash: Vec<u8>,
        player_id: Option<Vec<u8>>,
        player_ref: Option<Vec<u8>>,
    }

    #[derive(Clone)]
    struct TemplateFixture {
        source: &'static str,
        prefix: Vec<u8>,
        suffix: Vec<u8>,
        hash: Vec<u8>,
    }

    #[derive(Clone)]
    struct MuxChessFixture {
        mux: TemplateFixture,
        settle: TemplateFixture,
        pawn: TemplateFixture,
    }

    #[derive(Clone)]
    struct PlayerStateData {
        owner_hash: Vec<u8>,
        player_id: Vec<u8>,
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
        castle_rights: [u8; 4],
        en_passant_idx: i64,
        pending_src_idx: i64,
        pending_dst_idx: i64,
        pending_promo: i64,
        recent_castle: i64,
        draw_state: i64,
    }

    struct ActualTxArena {
        fix: MuxChessFixture,
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
        messages: BTreeMap<String, Vec<String>>,
        next_registration_index: u32,
    }

    struct TestOrchestrator {
        player: KeyedPlayer,
        arena: Rc<RefCell<ActualTxArena>>,
    }

    impl KeyedPlayer {
        fn from_seed(name: &str, seed: u8) -> Self {
            let secp = Secp256k1::new();
            let secret = SecretKey::from_slice(&[seed; 32]).expect("valid deterministic secret key");
            let keypair = Keypair::from_secret_key(&secp, &secret);
            let (x_only, _) = keypair.x_only_public_key();
            let pubkey_bytes = x_only.serialize().to_vec();
            let owner_hash = blake2b(&pubkey_bytes);
            Self { name: name.to_string(), keypair, pubkey_bytes, owner_hash, player_id: None, player_ref: None }
        }
    }

    impl TestOrchestrator {
        fn new(name: &str, seed: u8, arena: Rc<RefCell<ActualTxArena>>) -> Self {
            Self { player: KeyedPlayer::from_seed(name, seed), arena }
        }

        fn register(&mut self) -> Result<(), OrchestratorError> {
            self.arena.borrow_mut().register_player(&mut self.player)
        }

        fn inbox(&self) -> Vec<String> {
            self.arena.borrow_mut().drain_messages(&self.player.name)
        }

        fn invite(&self, other: &TestOrchestrator) {
            self.arena
                .borrow_mut()
                .messages
                .entry(other.player.name.clone())
                .or_default()
                .push(format!("invite:{}->{}", self.player.name, other.player.name));
        }

        fn start_game(&self, other: &TestOrchestrator) -> Result<(), OrchestratorError> {
            self.arena.borrow_mut().start_game(&self.player, &other.player)
        }

        fn play_e2e4(&self) -> Result<(), OrchestratorError> {
            self.arena.borrow_mut().play_pawn_double_step(&self.player)
        }

        fn surrender(&self) -> Result<(), OrchestratorError> {
            self.arena.borrow_mut().surrender(&self.player)
        }

        fn retire(&self) -> Result<(), OrchestratorError> {
            self.arena.borrow_mut().retire_player(&self.player)
        }
    }

    impl ActualTxArena {
        fn new() -> Result<Self, OrchestratorError> {
            let fix = build_fixture();
            let league_hash = vec![0x11u8; 32];
            let admin = vec![0x33u8; 32];
            let base_rating = 1200;
            let routes_commitment = routes_commitment(&packed_route_hashes(&fix));
            let player_template = compile_player_state(
                player_test_source(),
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
                league_test_source(),
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
                next_registration_index: 7,
            })
        }

        fn drain_messages(&mut self, name: &str) -> Vec<String> {
            self.messages.remove(name).unwrap_or_default()
        }

        fn register_player(&mut self, player: &mut KeyedPlayer) -> Result<(), OrchestratorError> {
            let index = self.next_registration_index;
            self.next_registration_index += 1;
            let txid = [0xabu8; 32];
            let player_id = blake2b([b"LeaguePlayerId".as_slice(), &txid, &index.to_le_bytes()].concat().as_slice());
            let player_ref = blake2b([player.owner_hash.as_slice(), player_id.as_slice()].concat().as_slice());

            let registered = compile_player_state(
                player_test_source(),
                PlayerStateArgs {
                    league_hash: &self.league_hash,
                    player_hash: &self.player_hash,
                    mux_hash: &self.fix.mux.hash,
                    routes_commitment: &routes_commitment(&packed_route_hashes(&self.fix)),
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
                    open_games: 0,
                    rating: self.base_rating,
                    games: 0,
                    wins: 0,
                    draws: 0,
                    losses: 0,
                },
            );
            Ok(())
        }

        fn start_game(&mut self, white: &KeyedPlayer, black: &KeyedPlayer) -> Result<(), OrchestratorError> {
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
                castle_rights: [1, 1, 1, 1],
                en_passant_idx: -1,
                pending_src_idx: -1,
                pending_dst_idx: -1,
                pending_promo: 0,
                recent_castle: 0,
                draw_state: 3,
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
                    Expr::bytes(packed_route_hashes(&self.fix)),
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
                    Expr::int(self.player_prefix_len),
                    Expr::int(self.player_suffix_len),
                ],
            );
            let outputs = vec![
                covenant_output(&next_white_contract, 0, self.covenant_id),
                covenant_output(&next_black_contract, 0, self.covenant_id),
                covenant_output(&opening_mux, 0, self.covenant_id),
            ];
            let entries = vec![covenant_utxo(&white_contract, self.covenant_id), covenant_utxo(&black_contract, self.covenant_id)];
            let mut tx = Transaction::new(
                1,
                vec![tx_input(0, white_placeholder), tx_input(1, black_placeholder)],
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
                    Expr::bytes(packed_route_hashes(&self.fix)),
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
            Ok(())
        }

        fn play_pawn_double_step(&mut self, white: &KeyedPlayer) -> Result<(), OrchestratorError> {
            let game = self.game.clone().ok_or_else(|| OrchestratorError("missing game".to_string()))?;
            let active = self.compile_mux(&game);
            let pending = GameStateData {
                white_player: game.white_player.clone(),
                black_player: game.black_player.clone(),
                board: game.board.clone(),
                turn: game.turn,
                status: game.status,
                castle_rights: game.castle_rights,
                en_passant_idx: game.en_passant_idx,
                pending_src_idx: square_idx(4, 1),
                pending_dst_idx: square_idx(4, 3),
                pending_promo: 0,
                recent_castle: 0,
                draw_state: 3,
            };
            let pawn = self.compile_worker(self.fix.pawn.source, &pending);
            let placeholder = entry_sigscript(
                &active,
                "route",
                vec![
                    Expr::int(0),
                    Expr::int(4),
                    Expr::int(1),
                    Expr::int(4),
                    Expr::int(3),
                    Expr::int(0),
                    Expr::int(0),
                    Expr::bytes(vec![0u8; 65]),
                    Expr::bytes(white.pubkey_bytes.clone()),
                    Expr::bytes(white.player_id.clone().ok_or_else(|| OrchestratorError("white missing player id".to_string()))?),
                    Expr::bytes(self.fix.pawn.prefix.clone()),
                    Expr::bytes(self.fix.pawn.suffix.clone()),
                ],
            );
            let outputs = vec![covenant_output(&pawn, 0, self.covenant_id)];
            let entries = vec![covenant_utxo(&active, self.covenant_id)];
            let mut tx = Transaction::new(1, vec![tx_input(0, placeholder)], outputs, 0, Default::default(), 0, vec![]);
            let sig = sign_tx_input_schnorr(&tx, &entries, 0, white);
            tx.inputs[0].signature_script = entry_sigscript(
                &active,
                "route",
                vec![
                    Expr::int(0),
                    Expr::int(4),
                    Expr::int(1),
                    Expr::int(4),
                    Expr::int(3),
                    Expr::int(0),
                    Expr::int(0),
                    Expr::bytes(sig),
                    Expr::bytes(white.pubkey_bytes.clone()),
                    Expr::bytes(white.player_id.clone().ok_or_else(|| OrchestratorError("white missing player id".to_string()))?),
                    Expr::bytes(self.fix.pawn.prefix.clone()),
                    Expr::bytes(self.fix.pawn.suffix.clone()),
                ],
            );
            execute_input_with_covenants(tx, entries, 0).map_err(|err| OrchestratorError(format!("route failed: {err}")))?;

            let mut board = game.board.clone();
            move_piece(&mut board, 4, 1, 4, 3);
            let next = GameStateData {
                white_player: game.white_player.clone(),
                black_player: game.black_player.clone(),
                board,
                turn: 1,
                status: 0,
                castle_rights: game.castle_rights,
                en_passant_idx: square_idx(4, 2),
                pending_src_idx: -1,
                pending_dst_idx: -1,
                pending_promo: 0,
                recent_castle: 0,
                draw_state: 3,
            };
            let next_mux = self.compile_mux(&next);
            let apply_sigscript = entry_sigscript(
                &pawn,
                "apply",
                vec![Expr::bytes(self.fix.mux.prefix.clone()), Expr::bytes(self.fix.mux.suffix.clone())],
            );
            let apply_tx = Transaction::new(
                1,
                vec![tx_input(0, apply_sigscript)],
                vec![covenant_output(&next_mux, 0, self.covenant_id)],
                0,
                Default::default(),
                0,
                vec![],
            );
            let apply_entries = vec![covenant_utxo(&pawn, self.covenant_id)];
            execute_input_with_covenants(apply_tx, apply_entries, 0)
                .map_err(|err| OrchestratorError(format!("apply failed: {err}")))?;

            self.game = Some(next);
            self.messages.entry("black".to_string()).or_default().push("move:white:e2e4".to_string());
            Ok(())
        }

        fn surrender(&mut self, black: &KeyedPlayer) -> Result<(), OrchestratorError> {
            let game = self.game.clone().ok_or_else(|| OrchestratorError("missing game".to_string()))?;
            let active = self.compile_mux(&game);
            let next = GameStateData {
                white_player: game.white_player.clone(),
                black_player: game.black_player.clone(),
                board: game.board.clone(),
                turn: game.turn,
                status: 1,
                castle_rights: game.castle_rights,
                en_passant_idx: -1,
                pending_src_idx: -1,
                pending_dst_idx: -1,
                pending_promo: 0,
                recent_castle: 0,
                draw_state: 3,
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
                    Expr::bytes(black.pubkey_bytes.clone()),
                    Expr::bytes(black.player_id.clone().ok_or_else(|| OrchestratorError("black missing player id".to_string()))?),
                    Expr::bytes(self.fix.mux.prefix.clone()),
                    Expr::bytes(self.fix.mux.suffix.clone()),
                ],
            );
            let outputs = vec![covenant_output(&terminal, 0, self.covenant_id)];
            let entries = vec![covenant_utxo(&active, self.covenant_id)];
            let mut tx = Transaction::new(1, vec![tx_input(0, placeholder)], outputs, 0, Default::default(), 0, vec![]);
            let sig = sign_tx_input_schnorr(&tx, &entries, 0, black);
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
                    Expr::bytes(black.pubkey_bytes.clone()),
                    Expr::bytes(black.player_id.clone().ok_or_else(|| OrchestratorError("black missing player id".to_string()))?),
                    Expr::bytes(self.fix.mux.prefix.clone()),
                    Expr::bytes(self.fix.mux.suffix.clone()),
                ],
            );
            execute_input_with_covenants(tx, entries, 0).map_err(|err| OrchestratorError(format!("surrender failed: {err}")))?;
            self.game = Some(next);
            Ok(())
        }

        fn settle_game(&mut self, white: &KeyedPlayer, black: &KeyedPlayer) -> Result<(), OrchestratorError> {
            let game = self.game.clone().ok_or_else(|| OrchestratorError("missing game".to_string()))?;
            let terminal = self.compile_mux(&game);
            let white_state = self.players.get(&white.name).cloned().ok_or_else(|| OrchestratorError("missing white".to_string()))?;
            let black_state = self.players.get(&black.name).cloned().ok_or_else(|| OrchestratorError("missing black".to_string()))?;
            let white_contract = self.compile_player(&white_state);
            let black_contract = self.compile_player(&black_state);

            let white_ref = white.player_ref.clone().ok_or_else(|| OrchestratorError("white missing player ref".to_string()))?;
            let black_ref = black.player_ref.clone().ok_or_else(|| OrchestratorError("black missing player ref".to_string()))?;
            let routed_settle = compile_settle_state(self.fix.settle.source, &self.player_hash, &white_ref, &black_ref, 1);
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
                vec![tx_input(0, mux_settle_sigscript)],
                vec![covenant_output(&routed_settle, 0, self.covenant_id)],
                0,
                Default::default(),
                0,
                vec![],
            );
            execute_input_with_covenants(mux_tx, vec![covenant_utxo(&terminal, self.covenant_id)], 0)
                .map_err(|err| OrchestratorError(format!("mux settle failed: {err}")))?;

            let mut next_white = white_state.clone();
            next_white.open_games -= 1;
            next_white.games += 1;
            next_white.wins += 1;
            next_white.rating = approx_updated_rating(white_state.rating, black_state.rating, 1000);
            let mut next_black = black_state.clone();
            next_black.open_games -= 1;
            next_black.games += 1;
            next_black.losses += 1;
            next_black.rating = approx_updated_rating(black_state.rating, white_state.rating, 0);

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
                    Expr::bytes(vec![0u8; 65]),
                    Expr::bytes(white.pubkey_bytes.clone()),
                    Expr::int(self.fix.settle.prefix.len() as i64),
                    Expr::int(self.fix.settle.suffix.len() as i64),
                    Expr::bytes(self.fix.settle.hash.clone()),
                ],
            );
            let black_placeholder = entry_sigscript(
                &black_contract,
                "delegate_settle",
                vec![
                    Expr::bytes(vec![0u8; 65]),
                    Expr::bytes(vec![0u8; 32]),
                    Expr::int(self.fix.settle.prefix.len() as i64),
                    Expr::int(self.fix.settle.suffix.len() as i64),
                    Expr::bytes(self.fix.settle.hash.clone()),
                ],
            );
            let outputs =
                vec![covenant_output(&settled_white, 0, self.covenant_id), covenant_output(&settled_black, 0, self.covenant_id)];
            let entries = vec![
                covenant_utxo(&routed_settle, self.covenant_id),
                covenant_utxo(&white_contract, self.covenant_id),
                covenant_utxo(&black_contract, self.covenant_id),
            ];
            let mut tx = Transaction::new(
                1,
                vec![tx_input(0, settle_sigscript), tx_input(1, white_placeholder), tx_input(2, black_placeholder)],
                outputs,
                0,
                Default::default(),
                0,
                vec![],
            );
            let white_sig = sign_tx_input_schnorr(&tx, &entries, 1, white);
            tx.inputs[1].signature_script = entry_sigscript(
                &white_contract,
                "delegate_settle",
                vec![
                    Expr::bytes(white_sig),
                    Expr::bytes(white.pubkey_bytes.clone()),
                    Expr::int(self.fix.settle.prefix.len() as i64),
                    Expr::int(self.fix.settle.suffix.len() as i64),
                    Expr::bytes(self.fix.settle.hash.clone()),
                ],
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
            Ok(())
        }

        fn retire_player(&mut self, white: &KeyedPlayer) -> Result<(), OrchestratorError> {
            let state = self.players.get(&white.name).cloned().ok_or_else(|| OrchestratorError("missing player".to_string()))?;
            let contract = self.compile_player(&state);
            let placeholder =
                entry_sigscript(&contract, "retire", vec![Expr::bytes(vec![0u8; 65]), Expr::bytes(white.pubkey_bytes.clone())]);
            let entries = vec![covenant_utxo(&contract, self.covenant_id)];
            let mut tx = Transaction::new(1, vec![tx_input(0, placeholder)], vec![], 0, Default::default(), 0, vec![]);
            let sig = sign_tx_input_schnorr(&tx, &entries, 0, white);
            tx.inputs[0].signature_script =
                entry_sigscript(&contract, "retire", vec![Expr::bytes(sig), Expr::bytes(white.pubkey_bytes.clone())]);
            execute_input_with_covenants(tx, entries, 0).map_err(|err| OrchestratorError(format!("retire failed: {err}")))?;
            self.players.remove(&white.name);
            Ok(())
        }

        fn compile_player(&self, state: &PlayerStateData) -> CompiledContract<'static> {
            compile_player_state(
                player_test_source(),
                PlayerStateArgs {
                    league_hash: &self.league_hash,
                    player_hash: &self.player_hash,
                    mux_hash: &self.fix.mux.hash,
                    routes_commitment: &routes_commitment(&packed_route_hashes(&self.fix)),
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
    }

    fn build_fixture() -> MuxChessFixture {
        let mux_source = load_test_contract_source(mux_contract_path());
        let settle_source = load_test_contract_source(settle_contract_path());
        let pawn_source = load_test_contract_source(pawn_contract_path());
        let dummy_board = standard_board();
        let game_ctor = vec![
            Expr::bytes(vec![0x11u8; 32]),
            Expr::bytes(vec![0x33u8; 32 * 9]),
            Expr::bytes(vec![0x21u8; 32]),
            Expr::bytes(vec![0x22u8; 32]),
            Expr::bytes(dummy_board),
            Expr::int(0),
            Expr::int(0),
            Expr::bytes(vec![1u8; 4]),
            Expr::int(-1),
            Expr::int(-1),
            Expr::int(-1),
            Expr::int(0),
            Expr::int(0),
            Expr::int(3),
        ];
        let settle_ctor =
            vec![Expr::bytes(vec![0x44u8; 32]), Expr::bytes(vec![0x21u8; 32]), Expr::bytes(vec![0x22u8; 32]), Expr::int(0)];
        MuxChessFixture {
            mux: template_fixture(mux_source, &game_ctor),
            settle: template_fixture(settle_source, &settle_ctor),
            pawn: template_fixture(pawn_source, &game_ctor),
        }
    }

    fn load_test_contract_source(path: &'static str) -> &'static str {
        Box::leak(load_contract_source(path).into_boxed_str())
    }

    fn league_test_source() -> &'static str {
        load_test_contract_source(league_contract_path())
    }

    fn player_test_source() -> &'static str {
        load_test_contract_source(player_contract_path())
    }

    fn template_fixture(source: &'static str, ctor: &[Expr<'_>]) -> TemplateFixture {
        let compiled = compile_contract(source, ctor, CompileOptions::default()).expect("compile template source succeeds");
        let layout = compiled.state_layout;
        let prefix = compiled.script[..layout.start].to_vec();
        let suffix = compiled.script[layout.start + layout.len..].to_vec();
        let hash = blake2b([prefix.as_slice(), suffix.as_slice()].concat().as_slice());
        TemplateFixture { source, prefix, suffix, hash }
    }

    fn packed_route_hashes(fix: &MuxChessFixture) -> Vec<u8> {
        let player_hash = {
            let player_template = compile_player_state(
                player_test_source(),
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
        out.extend_from_slice(&[0x13u8; 32]);
        out.extend_from_slice(&[0x14u8; 32]);
        out.extend_from_slice(&[0x15u8; 32]);
        out.extend_from_slice(&[0x16u8; 32]);
        out.extend_from_slice(&[0x17u8; 32]);
        out.extend_from_slice(&[0x18u8; 32]);
        out.extend_from_slice(&[0x19u8; 32]);
        out.extend_from_slice(&blake2b([fix.settle.hash.as_slice(), player_hash.as_slice()].concat().as_slice()));
        out
    }

    fn routes_commitment(route_hashes: &[u8]) -> Vec<u8> {
        blake2b(route_hashes)
    }

    fn standard_board() -> Vec<u8> {
        vec![
            0x04, 0x02, 0x03, 0x05, 0x06, 0x03, 0x02, 0x04, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x0c, 0x0a, 0x0b, 0x0d,
            0x0e, 0x0b, 0x0a, 0x0c,
        ]
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

    fn compile_game_state(source: &'static str, fix: &MuxChessFixture, state: &GameStateData) -> CompiledContract<'static> {
        let ctor = vec![
            Expr::bytes(fix.mux.hash.clone()),
            Expr::bytes(packed_route_hashes(fix)),
            Expr::bytes(state.white_player.clone()),
            Expr::bytes(state.black_player.clone()),
            Expr::bytes(state.board.clone()),
            Expr::int(state.turn),
            Expr::int(state.status),
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
        let ctor = vec![
            Expr::bytes(player_hash.to_vec()),
            Expr::bytes(white_hash.to_vec()),
            Expr::bytes(black_hash.to_vec()),
            Expr::int(status),
        ];
        compile_contract(source, &ctor, CompileOptions::default()).expect("compile settle state")
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

    fn sign_tx_input_schnorr(tx: &Transaction, entries: &[UtxoEntry], input_idx: usize, player: &KeyedPlayer) -> Vec<u8> {
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

    #[test]
    fn loads_template_family_with_real_route_commitment() {
        let planner = ChessTxPlanner::load().expect("template family loads");
        assert_eq!(planner.family.route_hashes.len(), 32 * 9);
        assert_eq!(planner.family.routes_commitment.len(), 32);
    }

    #[test]
    fn settlement_recipe_tracks_entitled_signers() {
        let planner = ChessTxPlanner::load().expect("template family loads");
        let white_win = planner.settlement_recipe(GameResult::WhiteWin);
        assert_eq!(white_win.settle_step.calls[1].signer, SignerRequirement::WhiteIfEntitled);
        assert_eq!(white_win.settle_step.calls[2].signer, SignerRequirement::None);

        let draw = planner.settlement_recipe(GameResult::Draw);
        assert_eq!(draw.settle_step.calls[1].signer, SignerRequirement::WhiteIfEntitled);
        assert_eq!(draw.settle_step.calls[2].signer, SignerRequirement::BlackIfEntitled);
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
        assert!(white_state.rating > 1200);
        assert!(black_state.rating < 1200);

        let retire = arena.retire_player(&white).expect("white retires");
        assert_eq!(retire.recipe_name, "retire");
        assert!(arena.player_account_snapshot(&white).is_err());
        assert_eq!(arena.history().len(), 8);
    }

    #[test]
    fn actual_txs_can_play_a_short_game_end_to_end() {
        let shared = Rc::new(RefCell::new(ActualTxArena::new().expect("actual arena builds")));
        let mut white = TestOrchestrator::new("white", 0x31, shared.clone());
        let mut black = TestOrchestrator::new("black", 0x32, shared.clone());

        white.register().expect("white register tx passes");
        black.register().expect("black register tx passes");

        white.invite(&black);
        let invite_mail = black.inbox();
        assert_eq!(invite_mail, vec!["invite:white->black".to_string()]);

        white.start_game(&black).expect("start game tx passes");
        white.play_e2e4().expect("white e2e4 txs pass");
        let move_mail = black.inbox();
        assert_eq!(move_mail, vec!["move:white:e2e4".to_string()]);

        black.surrender().expect("black surrender tx passes");
        shared.borrow_mut().settle_game(&white.player, &black.player).expect("settlement txs pass");
        white.retire().expect("retire tx passes");

        let arena = shared.borrow();
        assert!(arena.game.is_none());
        let white_state = arena.players.get("white");
        let black_state = arena.players.get("black").expect("black player remains");
        assert!(white_state.is_none());
        assert_eq!(black_state.open_games, 0);
        assert_eq!(black_state.losses, 1);
    }
}
