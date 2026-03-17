# Mux-Oriented Chess Modeling

## Goal

Define a route-based formal model for on-chain chess where:

- one canonical `ChessMux` state owns the game,
- specialized worker covenants validate bounded subproblems,
- each script stays small,
- the overall protocol still enforces full chess legality with L1 security.

This document does not replace [FORMAL_CHESS_STATE.md](./FORMAL_CHESS_STATE.md). That file defines the state target. This file defines how that state may be advanced through muxed covenant routes.

## Core idea

The chess transition is modeled as a composition of small verified steps:

$$
S_0 \xrightarrow{ChessMux} S_0 \xrightarrow{W_1} S_1 \xrightarrow{W_2} \dots \xrightarrow{W_n} S_n \xrightarrow{ChessMux} S_{n+1}
$$

where:

- `ChessMux` owns the canonical checkpoint state,
- each worker `W_i` checks one bounded claim,
- workers may form a bounded proof chain,
- only the final step must return control to `ChessMux`,
- the full move is legal iff the required route chain exists and every step verifies.

The design target is not minimal transaction count. The target is bounded script size with explicit security boundaries.

## State ownership

Only `ChessMux` is the canonical owner of durable chess state.

Workers do not introduce alternative state layouts. Every covenant in the route graph shares the same serialized `State` layout.

That shared layout should contain:

- the board and turn metadata,
- persistent rights such as castling and en passant state,
- any additional certificates required to avoid board sweeps,
- route-control metadata needed to bind phases together.

## Route graph

The general route graph is:

$$
ChessMux \to W_1 \to W_2 \to \dots \to W_n \to ChessMux
$$

for some bounded worker chain chosen by the move kind.

Likely worker classes:

1. `Pawn`
2. `Knight`
3. `SliderPath`
4. `King`
5. `Castle`
6. `EnPassant`
7. `KingSafety`

Some moves need only one worker. Others need a chain of workers across multiple transactions.

Examples:

- knight move:
  - `ChessMux -> Knight -> ChessMux`
- bishop move:
  - `ChessMux -> SliderPath -> ChessMux`
- castling:
  - `ChessMux -> Castle -> KingSafety -> ChessMux`
- a slider move with explicit post-check validation:
  - `ChessMux -> SliderPath -> Capture -> KingSafety -> ChessMux`
- a complex special move:
  - `ChessMux -> SpecialMove -> KingSafety -> ChessMux`

## Phase model

`ChessMux` should carry an explicit checkpoint phase field.

Minimal form:

- `0 = Idle`
- `1 = PendingRoute`

Likely final form:

- `0 = Idle`
- `1 = PendingPawnRoute`
- `2 = PendingKnightRoute`
- `3 = PendingSliderRoute`
- `4 = PendingKingRoute`
- `5 = PendingCastleRoute`
- `6 = PendingEnPassantRoute`
- `7 = PendingPromotionRoute`

In addition, intermediate workers may carry their own route-stage field:

- `route_step = 0, 1, 2, ...`

so that a multi-worker chain can progress without returning to `ChessMux` after every subcheck.

The phase is not just for control flow. It prevents route confusion and replay across unrelated move attempts.

## Move intent commitment

Before leaving `ChessMux`, the state should commit to the exact move intent and route plan.

At minimum:

- `from_idx`
- `to_idx`
- moving side
- route kind / expected next worker

Likely also:

- promotion choice,
- en-passant auxiliary square if relevant,
- any route-local witness commitment if a later step must be bound to a prior choice,
- current route-step if the proof continues through multiple workers.

This prevents a worker chain from validating a different move than the one selected by `ChessMux`.

## Worker contract obligations

Each worker should satisfy the same pattern:

1. reconstruct `prev_state`,
2. verify the current phase / route-step matches the worker,
3. verify the relevant local move rule,
4. compute the next shared `State`,
5. either hand off to the next committed worker template, or return to `ChessMux` if the route is complete.

Workers should not:

- choose the next script dynamically from witness input,
- own a different state schema,
- perform unrelated global validation,
- scan the full board.

## Security invariants

The muxed protocol must maintain these invariants.

### I1. Canonical ownership

The only durable checkpoint game state is the `ChessMux` state.

Workers are transient validators, not independent state owners.

### I2. Same-layout continuity

All routed contracts share exactly the same serialized `State` layout.

This is required for `validateOutputStateWithTemplate(...)` to be meaningful.

### I3. Route commitment

When `ChessMux` starts a route, the transaction must commit to the exact first worker template hash stored in state.

### I4. Route-chain commitment

Every intermediate worker must hand off only to the exact next template committed by the route state.

### I5. Final return commitment

The last worker in a route must return only to the exact `mux_hash` stored in state.

### I6. Intent continuity

Every worker in the chain verifies the move intent already committed in state.

### I7. No route injection

No user argument may directly choose a peer script hash. Script commitments are state-driven.

## Proof decomposition

The full legality proof for a move is decomposed into bounded subclaims.

Candidate decomposition:

1. move-shape legality
2. path emptiness for sliders
3. capture semantics
4. special-move semantics
5. post-move king safety

The purpose of the mux is to separate these subclaims into individually bounded scripts.

The purpose of worker chains is to allow these subclaims to be checked in sequence without forcing a return to `ChessMux` after each one.

## Modeling discipline

To keep the protocol honest, every formal transition model should obey these constraints:

- no `O(64)` board sweep,
- only bounded local reads,
- no hidden off-chain computation beyond explicit witness data,
- no worker that “knows” facts not committed in state or witness.

This matters whether the model is written in SIL, Rust, or pure math.

## Recommended incremental path

The muxed chess implementation should be grown in this order:

1. `ChessMux + Pawn`
2. `ChessMux + Knight`
3. `ChessMux + SliderPath`
4. `ChessMux + SliderPath -> KingSafety`
5. `ChessMux + King`
6. `ChessMux + Castle -> KingSafety`
7. `ChessMux + EnPassant`
8. `ChessMux + Promotion`

Only after the required worker chains exist should the full rule set be considered complete.

## What this document is for

Use this document to answer:

- which state belongs in `ChessMux`,
- which subclaim deserves its own worker,
- which worker chains should exist,
- which phase transitions are legal,
- which witness data must be bound into state,
- which invariants every route must preserve.

Use [FORMAL_CHESS_STATE.md](./FORMAL_CHESS_STATE.md) to answer:

- what the bounded no-sweep chess state itself should contain.
