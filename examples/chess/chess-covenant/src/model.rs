//! Pure Rust reference model for the Markov-style chess state proposed in
//! `examples/chess/FORMAL_CHESS_STATE.md`.
//!
//! This module is intentionally stricter than the current SIL contract work:
//! it models only those transition checks we believe can eventually be lowered
//! to SIL with bounded local work.
//!
//! Design choices in this phase:
//! - no full-board sweep inside `apply_move`
//! - exact king indices are stored in state
//! - slider safety is checked through king-centered ray certificates
//! - knight / pawn / king-adjacency threats are checked from local neighborhoods
//! - castling and en-passant captures are still marked unsupported
//! - checkmate / stalemate are not derived yet; `status` stays `Ongoing`
//!
//! The constructor helpers may scan the board to derive an initial state. The
//! transition path itself avoids any `O(64)` traversal and records simple stats
//! so we can validate the locality claim before translating the design to SIL.

use core::fmt;

pub const EMPTY: u8 = 0;
pub const WHITE_PAWN: u8 = 1;
pub const WHITE_KNIGHT: u8 = 2;
pub const WHITE_BISHOP: u8 = 3;
pub const WHITE_ROOK: u8 = 4;
pub const WHITE_QUEEN: u8 = 5;
pub const WHITE_KING: u8 = 6;
pub const BLACK_PAWN: u8 = 9;
pub const BLACK_KNIGHT: u8 = 10;
pub const BLACK_BISHOP: u8 = 11;
pub const BLACK_ROOK: u8 = 12;
pub const BLACK_QUEEN: u8 = 13;
pub const BLACK_KING: u8 = 14;

pub const CASTLE_WHITE_KINGSIDE: u8 = 1;
pub const CASTLE_WHITE_QUEENSIDE: u8 = 2;
pub const CASTLE_BLACK_KINGSIDE: u8 = 4;
pub const CASTLE_BLACK_QUEENSIDE: u8 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    White,
    Black,
}

impl Side {
    pub fn opponent(self) -> Self {
        match self {
            Self::White => Self::Black,
            Self::Black => Self::White,
        }
    }

    pub fn king_piece(self) -> u8 {
        match self {
            Self::White => WHITE_KING,
            Self::Black => BLACK_KING,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GameStatus {
    Ongoing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    North = 0,
    South = 1,
    East = 2,
    West = 3,
    NorthEast = 4,
    NorthWest = 5,
    SouthEast = 6,
    SouthWest = 7,
}

impl Direction {
    pub const ALL: [Direction; 8] = [
        Direction::North,
        Direction::South,
        Direction::East,
        Direction::West,
        Direction::NorthEast,
        Direction::NorthWest,
        Direction::SouthEast,
        Direction::SouthWest,
    ];

    pub fn delta(self) -> (i8, i8) {
        match self {
            Self::North => (0, 1),
            Self::South => (0, -1),
            Self::East => (1, 0),
            Self::West => (-1, 0),
            Self::NorthEast => (1, 1),
            Self::NorthWest => (-1, 1),
            Self::SouthEast => (1, -1),
            Self::SouthWest => (-1, -1),
        }
    }

    pub fn is_orthogonal(self) -> bool {
        matches!(self, Self::North | Self::South | Self::East | Self::West)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RayCert {
    pub first: Option<u8>,
    pub second: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RayCertificates {
    pub white: [RayCert; 8],
    pub black: [RayCert; 8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChessState {
    pub board: [u8; 64],
    pub turn: Side,
    pub status: GameStatus,
    pub white_king_idx: u8,
    pub black_king_idx: u8,
    pub ep_file: Option<u8>,
    pub castle_rights: u8,
    pub rays: RayCertificates,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoveWitness {
    pub from: u8,
    pub to: u8,
    pub promotion: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TransitionStats {
    pub path_square_reads: usize,
    pub ray_square_reads: usize,
    pub ray_refreshes: usize,
    pub neighborhood_reads: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedSpecialMove {
    Castling,
    EnPassantCapture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    GameFinished,
    MissingPiece,
    WrongSideToMove,
    FriendlyCapture,
    IllegalGeometry,
    BlockedPath,
    InvalidPromotion,
    MissingKing(Side),
    InvalidKingIndex(Side),
    KingOverlap,
    LeavesKingInCheck,
    UnsupportedSpecialMove(UnsupportedSpecialMove),
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for TransitionError {}

impl ChessState {
    /// Build a state from a full board by deriving king positions and all
    /// king-centered ray certificates. This constructor may scan the board.
    pub fn from_board(board: [u8; 64], turn: Side) -> Result<Self, TransitionError> {
        let white_king_idx = find_piece(&board, WHITE_KING).ok_or(TransitionError::MissingKing(Side::White))?;
        let black_king_idx = find_piece(&board, BLACK_KING).ok_or(TransitionError::MissingKing(Side::Black))?;
        if white_king_idx == black_king_idx {
            return Err(TransitionError::KingOverlap);
        }

        let mut state = Self {
            board,
            turn,
            status: GameStatus::Ongoing,
            white_king_idx,
            black_king_idx,
            ep_file: None,
            castle_rights: CASTLE_WHITE_KINGSIDE | CASTLE_WHITE_QUEENSIDE | CASTLE_BLACK_KINGSIDE | CASTLE_BLACK_QUEENSIDE,
            rays: RayCertificates::default(),
        };
        let mut stats = TransitionStats::default();
        state.rays.white = refresh_all_rays(&state.board, state.white_king_idx, &mut stats);
        state.rays.black = refresh_all_rays(&state.board, state.black_king_idx, &mut stats);
        Ok(state)
    }

    /// Standard chess starting position with full castling rights.
    pub fn standard() -> Self {
        let board = [
            0x04, 0x02, 0x03, 0x05, 0x06, 0x03, 0x02, 0x04, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x0c, 0x0a, 0x0b, 0x0d,
            0x0e, 0x0b, 0x0a, 0x0c,
        ];
        Self::from_board(board, Side::White).expect("standard board is valid")
    }

    /// Apply one move and return the next state plus bounded-work stats.
    pub fn apply_move_with_stats(&self, mv: MoveWitness) -> Result<(Self, TransitionStats), TransitionError> {
        if self.status != GameStatus::Ongoing {
            return Err(TransitionError::GameFinished);
        }
        self.validate_core_invariants()?;

        let mut stats = TransitionStats::default();
        let from = mv.from as usize;
        let to = mv.to as usize;
        if from >= 64 || to >= 64 || from == to {
            return Err(TransitionError::IllegalGeometry);
        }

        let moving_piece = self.board[from];
        if moving_piece == EMPTY {
            return Err(TransitionError::MissingPiece);
        }

        let mover = piece_side(moving_piece).ok_or(TransitionError::MissingPiece)?;
        if mover != self.turn {
            return Err(TransitionError::WrongSideToMove);
        }

        let target_piece = self.board[to];
        if piece_side(target_piece) == Some(mover) {
            return Err(TransitionError::FriendlyCapture);
        }
        if target_piece == mover.opponent().king_piece() {
            return Err(TransitionError::IllegalGeometry);
        }

        let from_idx = mv.from;
        let to_idx = mv.to;
        let from_x = x_of(from_idx);
        let from_y = y_of(from_idx);
        let to_x = x_of(to_idx);
        let to_y = y_of(to_idx);
        let dx = to_x - from_x;
        let dy = to_y - from_y;
        let abs_dx = dx.unsigned_abs();
        let abs_dy = dy.unsigned_abs();

        let kind = piece_kind(moving_piece).ok_or(TransitionError::IllegalGeometry)?;
        if kind == PieceKind::King && abs_dx == 2 && abs_dy == 0 {
            return Err(TransitionError::UnsupportedSpecialMove(UnsupportedSpecialMove::Castling));
        }

        // Validate geometry and local slider path emptiness.
        match kind {
            PieceKind::Pawn => self.validate_pawn_move(mover, from_x, from_y, to_x, to_y, target_piece, mv.promotion)?,
            PieceKind::Knight => {
                if !((abs_dx == 1 && abs_dy == 2) || (abs_dx == 2 && abs_dy == 1)) {
                    return Err(TransitionError::IllegalGeometry);
                }
            }
            PieceKind::Bishop => {
                if !(abs_dx == abs_dy && abs_dx > 0) {
                    return Err(TransitionError::IllegalGeometry);
                }
                if !path_clear(&self.board, from_idx, to_idx, &mut stats) {
                    return Err(TransitionError::BlockedPath);
                }
            }
            PieceKind::Rook => {
                if !((dx == 0 && abs_dy > 0) || (dy == 0 && abs_dx > 0)) {
                    return Err(TransitionError::IllegalGeometry);
                }
                if !path_clear(&self.board, from_idx, to_idx, &mut stats) {
                    return Err(TransitionError::BlockedPath);
                }
            }
            PieceKind::Queen => {
                let bishop_shape = abs_dx == abs_dy && abs_dx > 0;
                let rook_shape = (dx == 0 && abs_dy > 0) || (dy == 0 && abs_dx > 0);
                if !(bishop_shape || rook_shape) {
                    return Err(TransitionError::IllegalGeometry);
                }
                if !path_clear(&self.board, from_idx, to_idx, &mut stats) {
                    return Err(TransitionError::BlockedPath);
                }
            }
            PieceKind::King => {
                if !(abs_dx <= 1 && abs_dy <= 1 && (abs_dx + abs_dy) > 0) {
                    return Err(TransitionError::IllegalGeometry);
                }
            }
        }

        // Apply the local board update.
        let mut next = self.clone();
        next.board[from] = EMPTY;
        next.board[to] = resolve_placed_piece(moving_piece, mover, to_y, mv.promotion)?;
        next.turn = self.turn.opponent();
        next.ep_file = next_ep_file(moving_piece, from_x, dy);

        // Update king indices locally rather than discovering them from the board.
        if moving_piece == WHITE_KING {
            next.white_king_idx = to_idx;
        }
        if moving_piece == BLACK_KING {
            next.black_king_idx = to_idx;
        }

        // Update castling rights only from the touched home squares.
        next.castle_rights = next_castle_rights(self.castle_rights, moving_piece, from_idx, to_idx);

        // Refresh only the rays affected by the changed squares or king move.
        let changed = [from_idx, to_idx];
        let white_king_moved = moving_piece == WHITE_KING;
        let black_king_moved = moving_piece == BLACK_KING;
        next.rays.white =
            refresh_impacted_rays(&next.board, next.white_king_idx, self.rays.white, &changed, white_king_moved, &mut stats);
        next.rays.black =
            refresh_impacted_rays(&next.board, next.black_king_idx, self.rays.black, &changed, black_king_moved, &mut stats);

        // Reject moves that leave the moving side in check in the post-state.
        if next.is_king_in_check(mover, &mut stats) {
            return Err(TransitionError::LeavesKingInCheck);
        }

        Ok((next, stats))
    }

    pub fn apply_move(&self, mv: MoveWitness) -> Result<Self, TransitionError> {
        self.apply_move_with_stats(mv).map(|(state, _)| state)
    }

    /// Validate only the invariants that transitions rely on directly.
    pub fn validate_core_invariants(&self) -> Result<(), TransitionError> {
        if self.white_king_idx >= 64 {
            return Err(TransitionError::InvalidKingIndex(Side::White));
        }
        if self.black_king_idx >= 64 {
            return Err(TransitionError::InvalidKingIndex(Side::Black));
        }
        if self.white_king_idx == self.black_king_idx {
            return Err(TransitionError::KingOverlap);
        }
        if self.board[self.white_king_idx as usize] != WHITE_KING {
            return Err(TransitionError::InvalidKingIndex(Side::White));
        }
        if self.board[self.black_king_idx as usize] != BLACK_KING {
            return Err(TransitionError::InvalidKingIndex(Side::Black));
        }
        Ok(())
    }

    /// Full invariant check used in tests to validate certificate refresh.
    pub fn validate_full_invariants(&self) -> Result<(), TransitionError> {
        self.validate_core_invariants()?;
        let mut stats = TransitionStats::default();
        let expected_white = refresh_all_rays(&self.board, self.white_king_idx, &mut stats);
        let expected_black = refresh_all_rays(&self.board, self.black_king_idx, &mut stats);
        if self.rays.white != expected_white || self.rays.black != expected_black {
            return Err(TransitionError::IllegalGeometry);
        }
        Ok(())
    }

    fn validate_pawn_move(
        &self,
        mover: Side,
        from_x: i8,
        from_y: i8,
        to_x: i8,
        to_y: i8,
        target_piece: u8,
        promotion: Option<u8>,
    ) -> Result<(), TransitionError> {
        let dx = to_x - from_x;
        let dy = to_y - from_y;
        let abs_dx = dx.unsigned_abs();
        let target_is_empty = target_piece == EMPTY;

        match mover {
            Side::White => {
                let one_step = dx == 0 && dy == 1 && target_is_empty;
                let two_step = dx == 0
                    && dy == 2
                    && from_y == 1
                    && target_is_empty
                    && self.board[((from_y + 1) as usize) * 8 + from_x as usize] == EMPTY;
                let capture = abs_dx == 1 && dy == 1 && piece_side(target_piece) == Some(Side::Black);
                if abs_dx == 1 && dy == 1 && target_is_empty {
                    return Err(TransitionError::UnsupportedSpecialMove(UnsupportedSpecialMove::EnPassantCapture));
                }
                if !(one_step || two_step || capture) {
                    return Err(TransitionError::IllegalGeometry);
                }
            }
            Side::Black => {
                let one_step = dx == 0 && dy == -1 && target_is_empty;
                let two_step = dx == 0
                    && dy == -2
                    && from_y == 6
                    && target_is_empty
                    && self.board[((from_y - 1) as usize) * 8 + from_x as usize] == EMPTY;
                let capture = abs_dx == 1 && dy == -1 && piece_side(target_piece) == Some(Side::White);
                if abs_dx == 1 && dy == -1 && target_is_empty {
                    return Err(TransitionError::UnsupportedSpecialMove(UnsupportedSpecialMove::EnPassantCapture));
                }
                if !(one_step || two_step || capture) {
                    return Err(TransitionError::IllegalGeometry);
                }
            }
        }

        let promotes = (mover == Side::White && to_y == 7) || (mover == Side::Black && to_y == 0);
        if promotes && promotion.is_none() {
            return Err(TransitionError::InvalidPromotion);
        }
        if !promotes && promotion.is_some() {
            return Err(TransitionError::InvalidPromotion);
        }
        Ok(())
    }

    fn is_king_in_check(&self, side: Side, stats: &mut TransitionStats) -> bool {
        let king_idx = match side {
            Side::White => self.white_king_idx,
            Side::Black => self.black_king_idx,
        };
        let certs = match side {
            Side::White => &self.rays.white,
            Side::Black => &self.rays.black,
        };

        // Slider threats are already summarized in the king-centered ray certs.
        for (dir_idx, dir) in Direction::ALL.iter().enumerate() {
            if let Some(square) = certs[dir_idx].first {
                let piece = self.board[square as usize];
                if is_enemy_slider_for_direction(piece, side, *dir) {
                    return true;
                }
            }
        }

        // Knight threats are local to the king neighborhood.
        const KNIGHT_DELTAS: [(i8, i8); 8] = [(-2, -1), (-2, 1), (-1, -2), (-1, 2), (1, -2), (1, 2), (2, -1), (2, 1)];
        for (dx, dy) in KNIGHT_DELTAS {
            if let Some(square) = offset_square(king_idx, dx, dy) {
                stats.neighborhood_reads += 1;
                let piece = self.board[square as usize];
                if side == Side::White && piece == BLACK_KNIGHT {
                    return true;
                }
                if side == Side::Black && piece == WHITE_KNIGHT {
                    return true;
                }
            }
        }

        // Pawn threats are the two attack origins relative to the king.
        let pawn_sources = match side {
            Side::White => [(-1, 1), (1, 1)],
            Side::Black => [(-1, -1), (1, -1)],
        };
        for (dx, dy) in pawn_sources {
            if let Some(square) = offset_square(king_idx, dx, dy) {
                stats.neighborhood_reads += 1;
                let piece = self.board[square as usize];
                if side == Side::White && piece == BLACK_PAWN {
                    return true;
                }
                if side == Side::Black && piece == WHITE_PAWN {
                    return true;
                }
            }
        }

        // Adjacent kings are illegal and can be checked locally as well.
        for dy in -1..=1 {
            for dx in -1..=1 {
                if dx == 0 && dy == 0 {
                    continue;
                }
                if let Some(square) = offset_square(king_idx, dx, dy) {
                    stats.neighborhood_reads += 1;
                    let piece = self.board[square as usize];
                    if side == Side::White && piece == BLACK_KING {
                        return true;
                    }
                    if side == Side::Black && piece == WHITE_KING {
                        return true;
                    }
                }
            }
        }

        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PieceKind {
    Pawn,
    Knight,
    Bishop,
    Rook,
    Queen,
    King,
}

fn piece_kind(piece: u8) -> Option<PieceKind> {
    match piece {
        WHITE_PAWN | BLACK_PAWN => Some(PieceKind::Pawn),
        WHITE_KNIGHT | BLACK_KNIGHT => Some(PieceKind::Knight),
        WHITE_BISHOP | BLACK_BISHOP => Some(PieceKind::Bishop),
        WHITE_ROOK | BLACK_ROOK => Some(PieceKind::Rook),
        WHITE_QUEEN | BLACK_QUEEN => Some(PieceKind::Queen),
        WHITE_KING | BLACK_KING => Some(PieceKind::King),
        _ => None,
    }
}

fn piece_side(piece: u8) -> Option<Side> {
    match piece {
        WHITE_PAWN | WHITE_KNIGHT | WHITE_BISHOP | WHITE_ROOK | WHITE_QUEEN | WHITE_KING => Some(Side::White),
        BLACK_PAWN | BLACK_KNIGHT | BLACK_BISHOP | BLACK_ROOK | BLACK_QUEEN | BLACK_KING => Some(Side::Black),
        _ => None,
    }
}

fn resolve_placed_piece(piece: u8, side: Side, to_y: i8, promotion: Option<u8>) -> Result<u8, TransitionError> {
    let promotes =
        (side == Side::White && piece == WHITE_PAWN && to_y == 7) || (side == Side::Black && piece == BLACK_PAWN && to_y == 0);
    if promotes {
        let promo = promotion.ok_or(TransitionError::InvalidPromotion)?;
        let valid = match side {
            Side::White => matches!(promo, WHITE_KNIGHT | WHITE_BISHOP | WHITE_ROOK | WHITE_QUEEN),
            Side::Black => matches!(promo, BLACK_KNIGHT | BLACK_BISHOP | BLACK_ROOK | BLACK_QUEEN),
        };
        if !valid {
            return Err(TransitionError::InvalidPromotion);
        }
        return Ok(promo);
    }
    if promotion.is_some() {
        return Err(TransitionError::InvalidPromotion);
    }
    Ok(piece)
}

fn next_ep_file(piece: u8, from_x: i8, dy: i8) -> Option<u8> {
    if piece == WHITE_PAWN && dy == 2 {
        return Some(from_x as u8);
    }
    if piece == BLACK_PAWN && dy == -2 {
        return Some(from_x as u8);
    }
    None
}

fn next_castle_rights(mut rights: u8, moving_piece: u8, from_idx: u8, to_idx: u8) -> u8 {
    if moving_piece == WHITE_KING {
        rights &= !(CASTLE_WHITE_KINGSIDE | CASTLE_WHITE_QUEENSIDE);
    }
    if moving_piece == BLACK_KING {
        rights &= !(CASTLE_BLACK_KINGSIDE | CASTLE_BLACK_QUEENSIDE);
    }

    if from_idx == 7 || to_idx == 7 {
        rights &= !CASTLE_WHITE_KINGSIDE;
    }
    if from_idx == 0 || to_idx == 0 {
        rights &= !CASTLE_WHITE_QUEENSIDE;
    }
    if from_idx == 63 || to_idx == 63 {
        rights &= !CASTLE_BLACK_KINGSIDE;
    }
    if from_idx == 56 || to_idx == 56 {
        rights &= !CASTLE_BLACK_QUEENSIDE;
    }
    rights
}

fn x_of(idx: u8) -> i8 {
    (idx % 8) as i8
}

fn y_of(idx: u8) -> i8 {
    (idx / 8) as i8
}

fn offset_square(origin: u8, dx: i8, dy: i8) -> Option<u8> {
    let x = x_of(origin) + dx;
    let y = y_of(origin) + dy;
    if !(0..8).contains(&x) || !(0..8).contains(&y) {
        return None;
    }
    Some((y * 8 + x) as u8)
}

fn find_piece(board: &[u8; 64], target: u8) -> Option<u8> {
    board.iter().position(|piece| *piece == target).map(|idx| idx as u8)
}

fn aligned_direction(from: u8, to: u8) -> Option<Direction> {
    let dx = x_of(to) - x_of(from);
    let dy = y_of(to) - y_of(from);
    match (dx.signum(), dy.signum(), dx.unsigned_abs(), dy.unsigned_abs()) {
        (0, 1, 0, d) if d > 0 => Some(Direction::North),
        (0, -1, 0, d) if d > 0 => Some(Direction::South),
        (1, 0, d, 0) if d > 0 => Some(Direction::East),
        (-1, 0, d, 0) if d > 0 => Some(Direction::West),
        (1, 1, a, b) if a == b && a > 0 => Some(Direction::NorthEast),
        (-1, 1, a, b) if a == b && a > 0 => Some(Direction::NorthWest),
        (1, -1, a, b) if a == b && a > 0 => Some(Direction::SouthEast),
        (-1, -1, a, b) if a == b && a > 0 => Some(Direction::SouthWest),
        _ => None,
    }
}

fn refresh_all_rays(board: &[u8; 64], king_idx: u8, stats: &mut TransitionStats) -> [RayCert; 8] {
    let mut out = [RayCert::default(); 8];
    for dir in Direction::ALL {
        out[dir as usize] = refresh_ray(board, king_idx, dir, stats);
    }
    out
}

fn refresh_impacted_rays(
    board: &[u8; 64],
    king_idx: u8,
    previous: [RayCert; 8],
    changed: &[u8],
    king_moved: bool,
    stats: &mut TransitionStats,
) -> [RayCert; 8] {
    if king_moved {
        return refresh_all_rays(board, king_idx, stats);
    }

    let mut next = previous;
    let mut touched = [false; 8];
    for &square in changed {
        if let Some(dir) = aligned_direction(king_idx, square) {
            touched[dir as usize] = true;
        }
    }
    for dir in Direction::ALL {
        if touched[dir as usize] {
            next[dir as usize] = refresh_ray(board, king_idx, dir, stats);
        }
    }
    next
}

fn refresh_ray(board: &[u8; 64], king_idx: u8, dir: Direction, stats: &mut TransitionStats) -> RayCert {
    stats.ray_refreshes += 1;
    let (dx, dy) = dir.delta();
    let mut cert = RayCert::default();
    let mut x = x_of(king_idx) + dx;
    let mut y = y_of(king_idx) + dy;

    while (0..8).contains(&x) && (0..8).contains(&y) {
        let idx = (y * 8 + x) as u8;
        stats.ray_square_reads += 1;
        if board[idx as usize] != EMPTY {
            if cert.first.is_none() {
                cert.first = Some(idx);
            } else {
                cert.second = Some(idx);
                break;
            }
        }
        x += dx;
        y += dy;
    }

    cert
}

fn path_clear(board: &[u8; 64], from: u8, to: u8, stats: &mut TransitionStats) -> bool {
    let dir = match aligned_direction(from, to) {
        Some(dir) => dir,
        None => return false,
    };
    let (dx, dy) = dir.delta();
    let mut x = x_of(from) + dx;
    let mut y = y_of(from) + dy;
    let end_x = x_of(to);
    let end_y = y_of(to);

    while x != end_x || y != end_y {
        let idx = (y * 8 + x) as usize;
        stats.path_square_reads += 1;
        if board[idx] != EMPTY {
            return false;
        }
        x += dx;
        y += dy;
    }

    true
}

fn is_enemy_slider_for_direction(piece: u8, king_side: Side, dir: Direction) -> bool {
    let enemy = piece_side(piece) == Some(king_side.opponent());
    if !enemy {
        return false;
    }

    if dir.is_orthogonal() {
        matches!(piece, BLACK_ROOK | BLACK_QUEEN) && king_side == Side::White
            || matches!(piece, WHITE_ROOK | WHITE_QUEEN) && king_side == Side::Black
    } else {
        matches!(piece, BLACK_BISHOP | BLACK_QUEEN) && king_side == Side::White
            || matches!(piece, WHITE_BISHOP | WHITE_QUEEN) && king_side == Side::Black
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mv(from: u8, to: u8) -> MoveWitness {
        MoveWitness { from, to, promotion: None }
    }

    #[test]
    fn standard_state_derives_kings_and_certificates() {
        let state = ChessState::standard();
        assert_eq!(state.white_king_idx, 4);
        assert_eq!(state.black_king_idx, 60);
        assert!(state.validate_full_invariants().is_ok());
    }

    #[test]
    fn opening_sequence_stays_local_and_updates_metadata() {
        let state0 = ChessState::standard();

        let (state1, stats1) = state0.apply_move_with_stats(mv(12, 28)).expect("e2 -> e4");
        assert_eq!(state1.turn, Side::Black);
        assert_eq!(state1.ep_file, Some(4));
        assert!(stats1.path_square_reads <= 1);
        assert!(stats1.ray_refreshes <= 8);
        assert!(state1.validate_full_invariants().is_ok());

        let (state2, stats2) = state1.apply_move_with_stats(mv(52, 36)).expect("e7 -> e5");
        assert_eq!(state2.turn, Side::White);
        assert_eq!(state2.ep_file, Some(4));
        assert!(stats2.ray_refreshes <= 8);
        assert!(state2.validate_full_invariants().is_ok());

        let (state3, stats3) = state2.apply_move_with_stats(mv(6, 21)).expect("g1 -> f3");
        assert_eq!(state3.turn, Side::Black);
        assert_eq!(state3.ep_file, None);
        assert!(stats3.ray_refreshes <= 8);
        assert!(state3.validate_full_invariants().is_ok());
    }

    #[test]
    fn blocked_slider_move_is_rejected() {
        let state = ChessState::standard();
        let err = state.apply_move(mv(2, 38)).expect_err("c1 bishop is blocked in the initial position");
        assert_eq!(err, TransitionError::BlockedPath);
    }

    #[test]
    fn unsupported_castling_is_rejected() {
        let mut board = [EMPTY; 64];
        board[4] = WHITE_KING;
        board[7] = WHITE_ROOK;
        board[60] = BLACK_KING;
        let state = ChessState::from_board(board, Side::White).expect("minimal castling board is valid");
        let err = state.apply_move(mv(4, 6)).expect_err("castling is intentionally deferred");
        assert_eq!(err, TransitionError::UnsupportedSpecialMove(UnsupportedSpecialMove::Castling));
    }

    #[test]
    fn move_leaving_king_in_check_is_rejected_without_board_sweep() {
        let mut board = [EMPTY; 64];
        board[4] = WHITE_KING;
        board[12] = WHITE_ROOK;
        board[60] = BLACK_ROOK;
        board[56] = BLACK_KING;
        let state = ChessState::from_board(board, Side::White).expect("custom board is valid");

        let err = state.apply_move(mv(12, 13)).expect_err("moving the e2 rook should expose the white king");
        assert_eq!(err, TransitionError::LeavesKingInCheck);
    }

    #[test]
    fn promotion_requires_explicit_piece_code() {
        let mut board = [EMPTY; 64];
        board[4] = WHITE_KING;
        board[60] = BLACK_KING;
        board[48] = WHITE_PAWN;
        let state = ChessState::from_board(board, Side::White).expect("promotion test board is valid");

        let err = state.apply_move(mv(48, 56)).expect_err("promotion without witness piece is invalid");
        assert_eq!(err, TransitionError::InvalidPromotion);

        let promoted =
            state.apply_move(MoveWitness { from: 48, to: 56, promotion: Some(WHITE_QUEEN) }).expect("promotion witness should work");
        assert_eq!(promoted.board[56], WHITE_QUEEN);
        assert!(promoted.validate_full_invariants().is_ok());
    }
}
