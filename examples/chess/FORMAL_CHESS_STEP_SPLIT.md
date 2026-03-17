# Formal Chess Step Split

This note is narrower than `FORMAL_CHESS_MUX.md`.

Goal:
- describe the minimal extra state needed to split one move across multiple worker steps
- keep the design concrete enough to implement incrementally

Current lesson:
- `Mux -> directional worker -> Mux` is enough for pawn/knight/king
- it is not enough for straight sliders
- the expensive part is that the slider worker currently does both:
  - verify path / move legality
  - rewrite the board and finalize the move

So the next design target is:

`ChessMux -> FileUpCheck -> Finalize -> ChessMux`


## State

Shared across all scripts:

```text
mux_hash
pawn_hash
knight_hash
file_up_check_hash
file_down_check_hash
rank_left_check_hash
rank_right_check_hash
diag_up_right_check_hash
diag_up_left_check_hash
diag_down_right_check_hash
diag_down_left_check_hash
king_hash
finalize_hash

white_player
black_player
board[64]
turn

phase
pending_from_x
pending_from_y
pending_to_x
pending_to_y
pending_route
```

Minimal meaning:

```text
phase = 0  idle at mux
phase = 1  file_up verified, waiting for finalize
phase = 2  file_down verified, waiting for finalize
phase = 3  rank_left verified, waiting for finalize
phase = 4  rank_right verified, waiting for finalize
phase = 5  diag_up_right verified, waiting for finalize
phase = 6  diag_up_left verified, waiting for finalize
phase = 7  diag_down_right verified, waiting for finalize
phase = 8  diag_down_left verified, waiting for finalize
phase = 9  pawn route ready for finalize
phase = 10 knight route ready for finalize
phase = 11 king route ready for finalize
```

`pending_route` is probably redundant if `phase` already identifies the verified route.

So the true minimal version may be:
- no `pending_route`
- only `phase`


## Rule

Only `ChessMux` may start a move.

Only `Finalize` may rewrite the board and return to mux.

Intermediate check workers:
- must not rewrite the board
- must not flip the turn
- must only:
  - validate a subclaim
  - preserve the committed move intent
  - move `phase` from `idle` to a specific verified stage
  - route only to `Finalize`


## Mux Pseudocode

```text
policy_route(selector, from_x, from_y, to_x, to_y, sig, pk):
    require phase == idle
    require current player signature is valid
    require move coordinates are in bounds

    target_hash = route_hash(selector)
    verified_phase = phase_for_selector(selector)

    next_state = prev_state with:
        pending_from_x = from_x
        pending_from_y = from_y
        pending_to_x = to_x
        pending_to_y = to_y
        phase = idle

    output script = target_hash
```

Notes:
- `Mux` commits the move intent
- `Mux` does not yet claim the route is valid
- route-specific validity starts in the worker


## FileUpCheck Pseudocode

```text
policy_apply(prev_state):
    require phase == idle

    from = pending_from
    to = pending_to

    require coordinates are in bounds
    require moving piece is rook or queen of current side
    require destination does not hold own piece
    require to_x == from_x
    require to_y > from_y

    clear = 1
    for i in 0..6:
        if i < distance - 1:
            scan intermediate square
            if occupied:
                clear = 0
    require clear == 1

    next_state = prev_state with:
        phase = file_up_verified

    route only to finalize_hash
```

Important:
- board stays unchanged
- turn stays unchanged
- pending move stays unchanged


## Finalize Pseudocode

```text
policy_apply(prev_state):
    require phase == file_up_verified

    from = pending_from
    to = pending_to

    reload moving piece and target piece from board
    repeat only cheap consistency checks:
        require moving piece is rook or queen of current side
        require file-up geometry still matches
        require destination does not hold own piece

    next_board = board with piece moved from from_idx to to_idx

    next_state = prev_state with:
        board = next_board
        turn = 1 - turn
        phase = idle
        pending_* = -1

    route only to mux_hash
```

This is the key cost shift:
- expensive path loop happens in `FileUpCheck`
- expensive board rewrite happens in `Finalize`
- they no longer stack in one script


## Open Question

Do we need `Finalize` to repeat any legality checks at all?

Strict minimum:
- only check `phase == file_up_verified`
- trust prior step completely
- rewrite the board

Safer version:
- repeat a few cheap checks so `Finalize` is not just a blind copier

Current recommendation:
- repeat only cheap local checks
- do not repeat the path loop


## One Route Experiment

The first real implementation experiment should be exactly this:

`Mux -> FileUpCheck -> Finalize -> Mux`

and nothing else.

Success criteria:
- `FileUpCheck` stays under runtime op limit
- `Finalize` stays under runtime op limit
- combined flow is simpler than further fragmenting file movement by distance


## If This Works

Apply the same pattern to:
- `FileDownCheck`
- `RankLeftCheck`
- `RankRightCheck`
- diagonal directions

Then decide whether:
- pawn
- knight
- king

should also normalize onto the same `Check -> Finalize` pattern for conceptual consistency.
