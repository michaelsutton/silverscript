# Chess Covenant Architecture

This example uses a **Multiplexer pattern**.

The reason is straightforward: chess is too large to fit comfortably into one
script, and even if it did fit, forcing every move through one giant covenant
would be inefficient and hard to reason about.

So instead of one all-knowing contract, the protocol is split into:

- one canonical checkpoint contract: `ChessMux`
- many small worker contracts for bounded move families and challenge flows

The point is not to minimize transaction count. The point is to make the state
machine modular enough to be practical.

## Core Pattern

`ChessMux` is the durable owner of game state.

Workers are transient validators. A move is routed through mux into the relevant
worker, the worker checks one bounded claim, and control returns to mux.

This is what “multiplexer” means here:

1. mux authenticates the move attempt
2. mux commits the pending move into shared state
3. mux routes into the worker that matches the selected move family
4. the worker proves one bounded rule
5. the worker returns to mux with updated state

All contracts share the same serialized state layout. That is what lets them
behave like one split protocol instead of unrelated scripts.

## Why This Resembles Taproot

This pattern simulates something like a stateful version of Taproot branch
selection.

The protocol commits to many possible execution templates, but only one branch
is exercised for a given move. In that sense, mux plus worker hashes acts like a
contract-level branch selector.

The spender does not get to invent the next script. State decides which
templates are valid next steps.

## Practical Challenges of the Multiplexer Pattern

The pattern is useful, but it is not free.

The main challenges are:

- **cycles**: workers route back to mux, so the protocol is not a simple linear
  call tree
- **hash injection into state**: the state must carry the template hashes needed
  for future routing
- **template handling**: outputs are validated against script templates, not
  against arbitrary witness-supplied scripts

Those costs are acceptable here because the alternative is worse: a single chess
script would be too large, too entangled, and too expensive per move.

## Why Chess Still Has To Be Kept Small

Even with multiplexing, chess logic can still explode if every rule is enforced
eagerly and globally.

The main danger is broad board analysis:

- full board sweeps
- global attack recomputation
- “search all legal moves” style checks

Those patterns are exactly what make scripts grow out of control.

So the design keeps a second discipline:

- prefer bounded local checks
- avoid large board scans
- move difficult global rules into challenge flows

This is a reversal of philosophy. Instead of asking the mover to prove
everything immediately, the mover proves only the bounded local rule, and the
opponent is given a way to refute illegality.

## Challenge-Based Chess Logic

This repository repeatedly uses the same idea:

- prove the local move
- commit enough state for the opponent
- let the opponent challenge if the move violated a larger chess rule

Examples:

- ordinary king exposure is punished by a later king-capture proof
- castling stores challenge state so the opponent can prove that the king
  crossed or occupied a forbidden square

This is how the protocol still aims at full classical enforcement without
forcing every move worker to solve all of chess at once.

## Draw Negotiation

Draw claims use the same adversarial mindset.

Instead of trying to prove “no legal move exists” by sweeping the board, the
protocol turns the claim into a short dispute game.

The board is not physically flipped. The protocol flips interpretation:

- the board stays unchanged
- the signer stays their real side
- workers derive an `effective_turn`
- each side temporarily plays the other side

That keeps draw negotiation small enough to reuse the normal move workers.

## Timeout

Timeout is the general liveness mechanism for multiplexed state machines.

Once a protocol is split across multiple templates, some states can stall:

- a player may refuse to choose the next route from mux
- a worker state may be committed but never advanced

Timeout is how the protocol guarantees progress.

In chess terms, this is not a weird add-on. It is a necessary part of the game
model, especially if the protocol is expected to behave more like blitz chess
than correspondence chess.

The split used here is:

- mux timeout is opponent-signed, because mux is still a strategic choice state
- worker timeout is permissionless, because a stuck worker state has an
  objective resolution

Timeouts are measured in DAA score, so the protocol can treat elapsed chain time
as part of the game.

## Design Rules

1. Keep durable state in mux.
2. Keep workers narrow and reusable.
3. Use state-driven template commitments.
4. Use challenges for rules that are easier to refute than to prove eagerly.
5. Use timeout as the universal liveness layer.
6. Avoid broad board sweeps.
7. Prefer semantic reinterpretation over physical board rewrites when building
   dispute subgames.
