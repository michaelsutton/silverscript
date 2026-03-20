# Dependencies And Template Injection

This is the core structural picture.

```mermaid
flowchart TD
    L[League registration lane<br/>immutable self-recreating contract]
    P[Player<br/>persistent score contract]
    G[Game<br/>episodic chess contract]

    L -- registers --> P
    P -- starts --> G
    G -- settles into --> P

    L -. injects player_hash .-> P
    L -. injects mux_hash .-> P
    L -. injects route_hashes .-> P

    P -. injects mux_hash .-> G
    P -. injects route_hashes .-> G

    G -. validates Player inputs by player_hash .-> P
    P -. delegates to Game leader by mux_hash .-> G
```

## What each layer needs to know

```mermaid
flowchart LR
    subgraph League
        LH[player_hash]
        LM[mux_hash]
        LR[route_hashes]
    end

    subgraph Player
        PM[mux_hash]
        PX[route_hashes]
        PP[player_id]
        PO[owner]
        PR[rating]
    end

    subgraph Game
        GW[white_player_ref]
        GB[black_player_ref]
        GR[result / terminal state]
    end

    LH --> Player
    LM --> Player
    LR --> Player

    PM --> Game
    PX --> Game
    PP --> Game

    GW --> Player
    GB --> Player
```

Today `player_id` does not come from injected League state. It is derived as
`blake2b("LeaguePlayerId" || outpoint_txid || outpoint_index_le32)`, so the
domain is fixed by the contract code itself.

Today the game state binds each side as `blake2b(owner || player_id)`, not as a
raw `player_id`. That keeps the game-side footprint to one field per side while
still letting settlement recover canonical player ids from `Player` inputs.

## Why shared covenant id is not enough by itself

With one shared covenant id:

- `League`, `Player`, and `Game` are all in the same covenant family
- covenant-id grouping is enough to prove they belong to the same system
- covenant-id grouping is **not** enough to prove their role

So settlement needs both:

1. same cov-id group
2. role validation by template hash

That is why the design depends on:

- injected `player_hash`, `mux_hash`, and `route_hashes`
- input-side template validation primitives
