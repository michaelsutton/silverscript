# Dependencies And Template Injection

This is the core structural picture.

```mermaid
flowchart TD
    L[League mint lane<br/>immutable self-recreating contract]
    P[Player<br/>persistent score contract]
    G[Game<br/>episodic chess contract]

    L -- mints --> P
    P -- starts --> G
    G -- settles into --> P

    L -. injects player_hash .-> P
    L -. injects game_hash .-> P
    L -. injects id_domain .-> P

    P -. injects game_hash .-> G
    G -. injects player_hash .-> G

    G -. validates Player inputs by player_hash .-> P
    P -. delegates to Game leader by game_hash .-> G
```

## What each layer needs to know

```mermaid
flowchart LR
    subgraph League
        LH[player_hash]
        LG[game_hash]
        LD[id_domain]
    end

    subgraph Player
        PG[game_hash]
        PP[player_id]
        PO[owner]
        PR[rating]
    end

    subgraph Game
        GP[player_hash]
        GW[white_player_id]
        GB[black_player_id]
        GR[result / terminal state]
    end

    LH --> Player
    LG --> Player
    LD --> Player

    PG --> Game
    PP --> Game

    GP --> Player
    GW --> Player
    GB --> Player
```

## Why shared covenant id is not enough by itself

With one shared covenant id:

- `League`, `Player`, and `Game` are all in the same covenant family
- covenant-id grouping is enough to prove they belong to the same system
- covenant-id grouping is **not** enough to prove their role

So settlement needs both:

1. same cov-id group
2. role validation by template hash

That is why the design depends on:

- injected `player_hash` and `game_hash`
- input-side template validation primitives

