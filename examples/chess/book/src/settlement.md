# Settlement Auth Shape

Target transaction:

`(game) -> (settle)` then `(settle, player, player) -> (player, player)`

The intended auth split is:

- `ChessMux` routes terminal state into `ChessSettle`
- the terminal route tail is a commitment to `blake2b(settle_template || player_template)`
- `ChessSettle` is the settlement leader
- both `Player` inputs are delegates
- entitled delegates sign, while losing delegates stay signature-free
- current first cut keeps rating unchanged and only settles win/draw/loss counts

```mermaid
sequenceDiagram
    participant G as Game input
    participant S as Settle input
    participant PW as Player input A
    participant PB as Player input B
    participant OW as Player output A
    participant OB as Player output B

    G->>S: witness settle template and player_template, then route terminal state
    S->>S: verify terminal chess result
    S->>PW: verify input template == player_template
    S->>PB: verify input template == player_template
    S->>S: verify bound player refs match inputs
    S->>OW: decrement open_games
    S->>OB: decrement open_games
    S->>OW: verify output template == player_template
    S->>OB: verify output template == player_template
    S->>OW: verify stat transition
    S->>OB: verify stat transition

    PW->>S: if owed funds, sign delegate; else stay unsigned
    PB->>S: if owed funds, sign delegate; else stay unsigned
```

## Current Slice

What is implemented now:

- `ChessMux` routes a terminal mux state into `ChessSettle`
- that route is authenticated against the tail commitment
  `blake2b(settle_template || player_template)`
- `ChessSettle` settles into two `Player` outputs
- settlement requires both players to have `open_games > 0`
- settlement decrements `open_games` for both players
- settlement increments `games`
- terminal result updates `wins` / `draws` / `losses`
- a winning player must sign its `delegate_settle` path
- on draw, both players must sign their `delegate_settle` paths
- a losing player may still delegate settlement unsigned
- `rating` is intentionally left unchanged for now

This means the durable layer now has one concrete lifecycle invariant:

- a `Player` can retire only when `open_games == 0`

And one first funds-oriented auth invariant:

- the players who are plausibly entitled to payout already consent on chain
- payout shape itself is still left to off-chain review for now

What is still open:

- rating math
- stronger guarantees around output ordering or template commitments if we want
  delegates to reason more directly about the produced `Player` outputs
- whether `Player.start_game` should also require `open_games == 0` and forbid
  overlapping games entirely
