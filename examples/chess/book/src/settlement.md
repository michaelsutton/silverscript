# Settlement Auth Shape

Target transaction:

`(game, player, player) -> (player, player)`

The intended auth split is:

- `Game` is the leader
- both `Player` inputs are delegates

```mermaid
sequenceDiagram
    participant G as Game input
    participant PW as Player input A
    participant PB as Player input B
    participant OW as Player output A
    participant OB as Player output B

    G->>G: verify terminal chess result
    G->>PW: verify input template == player_hash
    G->>PB: verify input template == player_hash
    G->>G: verify bound player refs match inputs
    G->>OW: verify output template == player_hash
    G->>OB: verify output template == player_hash
    G->>OW: verify rating transition
    G->>OB: verify rating transition

    PW->>G: delegate only if leader template == mux_hash
    PB->>G: delegate only if leader template == mux_hash
```
