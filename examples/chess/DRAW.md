# Draw Negotiation Design

## Goal

Avoid full on-chain search for stalemate-like claims.

Instead of proving directly that the side to move has no legal move, the protocol
turns the claim into a short adversarial subgame that reuses the ordinary move
workers.

The governing claim is:

> The side to move has no move that avoids immediate loss under the covenant
> rules.

This is intentionally narrower than full classical draw adjudication. It matches
this project’s existing on-chain model, where illegal or losing play is
punishable by a concrete king-capture proof.

## Core Reduction

A draw claim flips control semantics without flipping the board.

- The board stays unchanged.
- The authenticated player still signs as their real side.
- In draw negotiation, move ownership is checked against the opposite side.
- If a player proves a king capture while piloting the opponent’s side, that
  player wins the draw dispute.

So the dispute becomes:

1. A claims that A has no safe move.
2. B tries to refute the claim by playing one move for A.
3. A then tries to show that even after that move, B can immediately win.

This keeps the proof game bounded and reuses the existing move machinery.

## State Fields

The minimal design uses a single extra state field:

- `draw_state: int`

Encoding:

- `0`: normal play
- `1`: draw claimed; the responder now plays a move for the claimant side
- `2`: counterplay step; the claimant now plays a move for the responder side

No board transformation is needed.
No additional draw-specific board fields are needed.

## Mux Entry

Draw claim uses the normal mux `route(...)` entrypoint.

Selector layout currently reserves:

- `8`: draw claim

A draw claim is valid only from ordinary idle play:

- `status == 0`
- `draw_state == 0`
- `recent_castle == 0`

The draw-claim selector uses a fixed dummy move tuple:

- `from_x = 0`
- `from_y = 0`
- `to_x = 0`
- `to_y = 0`
- `promo_piece = 0`

On success, mux outputs back to the mux template with:

- `turn = 1 - turn`
- `draw_state = 1`
- pending move fields cleared
- `en_passant_idx = -1`
- `recent_castle = 0`

This means the next authenticated player is the responder to the draw claim.

During draw negotiation, routing is restricted to the ordinary move workers:

- `pawn`
- `knight`
- `vert`
- `horiz`
- `diag`
- `king`

Castling and castle-challenge routes are intentionally disabled in draw mode.
For this protocol, the draw subgame is restricted to the ordinary move workers.
That keeps the dispute strictly two-ply and avoids introducing a nested
castling-challenge subprotocol inside the draw negotiation itself.

## Effective Turn

Workers derive an `effective_turn`:

- normal play: `effective_turn = turn`
- draw negotiation: `effective_turn = 1 - turn`

This is the only semantic flip needed.

Interpretation:

- `turn` still identifies the real actor who signed the mux route.
- `effective_turn` identifies which side’s pieces that actor is temporarily
  allowed to move.

That lets the protocol reuse the ordinary move workers without rewriting the
board.

## Worker Rules in Draw Mode

Each ordinary move worker can be patched with a small draw-aware branch.

### Ownership

Piece ownership and friendly-capture checks use `effective_turn`, not `turn`,
when `draw_state > 0`.

### Non-terminal success

On a successful non-terminal move:

- `draw_state == 1` advances to `draw_state = 2`
- `draw_state == 2` does not return to ordinary play if no king-capture proof is
  found; that failure means the original draw claim was false and the claimant
  loses immediately

Turn still flips as usual after the move.

### Terminal success

In normal play, king capture awards the win to the moving side in the usual way.

In draw negotiation, king capture still proves success, but the winner is the
real actor identified by `turn`, not the side identified by `effective_turn`.

That is the key dispute rule:

- if you prove a win while temporarily piloting the opponent’s side, you win the
  draw dispute yourself.

## Two-Ply Flow

The draw negotiation is a fixed two-ply subgame.

### Step 1: Claim

The side to move claims draw.

State transition:

- `draw_state: 0 -> 1`
- `turn: A -> B`

Meaning:

- B now tries to refute the claim by making one move for A.

### Step 2: Refutation Attempt

B makes a normal routed move, but workers validate it against A’s pieces via
`effective_turn`.

Outcomes:

- If the move immediately proves success for B under the dispute rules, B wins.
- Otherwise the move is applied normally and the state advances to:
  - `draw_state: 1 -> 2`
  - `turn: B -> A`

### Step 3: Counterplay

A now makes one normal routed move, but workers validate it against B’s pieces
via `effective_turn`.

Outcomes:

- If A proves success, A wins the dispute.
- If A cannot prove success with the chosen move, the original draw claim was
  false and A loses immediately

This design keeps the dispute bounded. It does not require open-ended recursive
search.

## Why There Are No Special Draw Piece Workers

The clean reduction is to change semantics, not move geometry.

Because the board is unchanged and only side interpretation flips, ordinary move
workers can continue to validate:

- geometry
- path clearance
- promotions
- captures
- board rewrite

Only these parts need draw-aware behavior:

- side ownership checks
- winner attribution on king capture
- `draw_state` progression

That is much smaller than introducing a second family of draw-specific move
workers.

## Deliberate Scope Limits

This design addresses only the bounded “no safe move” dispute.

It does not cover:

- threefold repetition
- 50-move rule
- insufficient material
- agreed draw as a separate explicit protocol action
- full classical stalemate adjudication via exhaustive move search

Those can be added later as separate protocol features if needed.

## Terminal State Encoding

Terminal outputs may retain a nonzero `draw_state`.

This is intentional. Once `status` is terminal, the game is already settled, so
the draw-state value no longer drives future control flow. Keeping `draw_state`
in the terminal output is useful as protocol metadata because it records that
the game ended during draw negotiation, and in which phase the decisive result
occurred.
