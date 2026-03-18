# Chess Rules Coverage

This document tracks how the current mux/worker chess protocol relates to
classical chess rules.

It is an audit document, not a promise that every row is already complete.

## Status Legend

- `bounded`: enforced directly by the active mux or worker spend
- `challenge`: enforceable by the opponent through an explicit protocol path
- `partial`: some support exists, but not full classical enforcement yet
- `missing`: no complete on-chain protocol path yet

## Coverage Matrix

| Rule Family | Current Status | Current Mechanism | Evidence |
| --- | --- | --- | --- |
| Side to move authorization | bounded | `ChessMux` authenticates the current signer before routing | `muxed_chess_routes_all_move_families` |
| Piece geometry by move family | bounded | each worker validates only its own move family | `muxed_chess_routes_all_move_families` |
| Slider path emptiness | bounded | vertical, horizontal, and diagonal workers scan the bounded lane | `muxed_chess_routes_all_move_families`, `pawn_double_step_blocked_by_occupied_middle_square_fails` |
| Pawn promotion choice | bounded | pawn worker requires a promotion piece only on the back rank | `pawn_underpromotion_to_knight_succeeds`, `pawn_promotion_requires_choice`, `non_promotion_pawn_move_rejects_promotion_choice` |
| En passant | bounded | pawn worker tracks and consumes `en_passant_idx` | `white_en_passant_capture_succeeds`, `black_en_passant_capture_succeeds`, `expired_en_passant_attempt_fails` |
| Castling structure | bounded | castle worker checks home square, rights bit, corner rook, empty lane | `ordinary_reply_after_castle_clears_recent_castle` |
| Castling through / into attack | challenge | `recent_castle` plus castle-challenge prep rewrites a proof board and forwards into an ordinary worker | `castle_start_square_challenge_by_pawn_succeeds`, `castle_transit_square_challenge_by_rook_succeeds`, `castle_destination_square_challenge_by_rook_succeeds`, `white_queenside_castle_destination_challenge_succeeds`, `black_kingside_castle_start_challenge_by_pawn_succeeds`, `black_queenside_castle_transit_challenge_by_rook_succeeds` |
| Draw negotiation flow | partial | custom two-phase draw dispute reuses ordinary workers and mux timeout | `claim_draw_flips_turn_and_enters_draw_state`, `knight_draw_negotiation_flips_side_control_and_false_claim_loses`, `draw_mode_reuses_ordinary_workers`, `draw_mode_disallows_castle_and_castle_challenge_routes` |
| Timeout / liveness | bounded | mux timeout is opponent-signed, worker timeout is permissionless | `knight_worker_timeout_rescues_invalid_committed_state` |
| Terminal win by king capture | bounded | workers set terminal status when the enemy king is captured | `capturing_enemy_king_sets_terminal_status`, `knight_draw_capture_awards_win_to_the_actor`, `pawn_draw_capture_awards_win_to_the_actor` |
| Ordinary no-self-check / must-answer-check semantics | partial | the design intends these violations to reduce to punishable next-ply king capture, but that reduction is not yet documented and covered as a protocol theorem | no complete tx coverage yet |
| Checkmate reduction to forced king capture | partial | mate does not need a separate eager terminal predicate here; the intended reduction is surrender or a reply after which the king is capturable, but that reduction is not yet covered end-to-end in theorem-style tx tests | no direct tx coverage yet |
| Surrender / resignation | missing | no explicit concede path yet | none |
| Stalemate as a direct terminal proof | missing | no dedicated on-chain stalemate path yet | none |
| Threefold repetition | missing | no repetition state or proof path yet | none |
| Fifty-move rule | missing | no half-move clock state or proof path yet | none |
| Insufficient material draw | missing | no dedicated state or proof path yet | none |
| Value settlement on win / draw | missing | current example demonstrates game-state transitions, not final KAS settlement | none |

## Immediate Gaps

The highest-value unresolved areas are:

- documented and tested reduction from ordinary check-evasion failures to punishable king capture
- explicit surrender / resignation
- rare draw rules such as repetition and the fifty-move rule
- termination semantics beyond king capture, timeout, and accepted draw
- value settlement after win or draw

## Expected Maintenance

When rule support changes, this file should move the relevant row from
`partial` or `missing` into `bounded` or `challenge`, and update the evidence
column to point at the concrete transaction tests that prove it.
