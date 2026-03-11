# Markov-Efficient Chess State

## Goal

Construct a fixed-size state representation for chess such that a state transition

$$
T : \mathcal{S} \times \mathcal{W} \to \mathcal{S} \cup \{\bot\}
$$

can be checked and applied with work proportional to a constant number of local paths of length at most $7$, rather than by scanning all $64$ squares.

Here:

- $\mathcal{S}$ is the set of legal game states.
- $\mathcal{W}$ is the set of move witnesses.
- $\bot$ means "invalid transition".

The target is not "constant time" in the RAM-model sense, but more specifically:

$$
\text{work}(T) = O(8)
$$

meaning a bounded number of inspections of paths/neighborhoods of maximum length $8$, with no $O(64)$ board sweep.

## 1. Base Objects

Let the square set be

$$
Q = \{0,\dots,63\}.
$$

Let the piece alphabet be

$$
\Sigma = \{ \varnothing \} \cup \{ wP,wN,wB,wR,wQ,wK,bP,bN,bB,bR,bQ,bK \}.
$$

The board is a function

$$
B : Q \to \Sigma.
$$

We assume the stored board is internally consistent and legal as a chess position.

## 2. State Representation

Define the state as

$$
S = (B,\tau,\kappa,\varepsilon,\mu,\rho,\nu,\pi,\chi),
$$

where:

- $B \in \Sigma^{64}$: board array.
- $\tau \in \{W,B\}$: side to move.
- $\kappa = (k_W, k_B) \in Q^2$: exact king locations.
- $\varepsilon \in \{\bot,0,\dots,7\}$: en-passant file or none.
- $\mu \in \{0,1\}^4$: castling rights.
- $\rho$: king-ray certificates.
- $\nu$: king-knight certificates.
- $\pi$: king-pawn certificates.
- $\chi = (\chi_W,\chi_B)$: cached "in check" bits.

All components are fixed-size.

## 3. King-Centered Certificates

The key idea is that legality after a move is determined by:

1. whether the moving side's king is attacked in the post-state,
2. whether king motion is legal,
3. whether special moves are legal,
4. whether a sliding move path is empty.

All of these are local.

### 3.1 Ray Set

Let

$$
D = \{N,S,E,W,NE,NW,SE,SW\}
$$

be the eight king rays.

For a king square $k$ and a direction $d \in D$, let

$$
\operatorname{Ray}(k,d) = (q_1,\dots,q_m)
$$

be the ordered list of squares from $k$ outward in direction $d$, with $m \le 7$.

### 3.2 First/Second Occupancy Certificates

For each side $c \in \{W,B\}$ and each $d \in D$, store:

- $\rho_1(c,d)$: the first occupied square on $\operatorname{Ray}(k_c,d)$, or $\bot$,
- $\rho_2(c,d)$: the second occupied square on $\operatorname{Ray}(k_c,d)$, or $\bot$.

These two values are enough to encode both:

- direct slider attacks on the king,
- absolute pins of the first friendly blocker on that ray.

### 3.3 Knight Certificates

Let $N_1(k),\dots,N_8(k)$ be the at most eight knight-origin squares attacking square $k$.

For each king $k_c$, store:

$$
\nu(c,i) = B(N_i(k_c))
$$

for each valid origin, and $\varnothing$ for off-board origins.

### 3.4 Pawn Certificates

For each king $k_c$, store the two enemy-pawn origin squares that could attack $k_c$:

$$
\pi(c,1), \pi(c,2).
$$

Operationally this can be stored either as piece codes on those two squares or as those two square indices plus a derived check.

### 3.5 Check Bit

The cached bit $\chi_c$ satisfies

$$
\chi_c = 1 \iff k_c \text{ is under attack in } B.
$$

It is derived from $\rho,\nu,\pi,\kappa$, not independently trusted.

## 4. Why $\rho_2$ Matters

A single first-occupancy certificate detects checks, but not pins. The second occupancy makes pins local.

For a fixed king $k_c$ and direction $d$:

- If $\rho_1(c,d)$ is an enemy rook/queen on an orthogonal ray, or bishop/queen on a diagonal ray, then the king is in direct check.
- If $\rho_1(c,d)$ is a friendly piece $x$, and $\rho_2(c,d)$ is a compatible enemy slider, then $x$ is absolutely pinned to $k_c$.

This means the transition function can reject many illegal moves before doing any wider post-state analysis.

## 5. Check Predicate

Define a function

$$
\operatorname{SliderThreat}(c,d) \in \{0,1\}
$$

by:

$$
\operatorname{SliderThreat}(c,d)=1
$$

iff $\rho_1(c,d)$ is occupied by an enemy slider compatible with direction $d$.

Then

$$
\chi_c =
\left(\bigvee_{d \in D}\operatorname{SliderThreat}(c,d)\right)
\vee \operatorname{KnightThreat}(c)
\vee \operatorname{PawnThreat}(c)
\vee \operatorname{KingAdjacencyThreat}(c).
$$

Every term is $O(1)$ once the certificates are sound.

## 6. Move Witness

Let a move witness be

$$
W = (u,v,\sigma,\lambda),
$$

where:

- $u,v \in Q$: source and destination,
- $\sigma$: optional promotion piece,
- $\lambda$: auxiliary local witness data.

The auxiliary data $\lambda$ may contain:

- ray direction and path length for a sliding move,
- en-passant capture square,
- rook source/destination for castling.

No witness contains global information.

## 7. Transition Strategy

Let $c = \tau$ be the moving side and $\bar c$ the opponent.

The transition has four stages:

1. local piece-motion validation,
2. local board update,
3. local certificate refresh,
4. post-state king-safety check.

The changed-square set $\Delta$ always satisfies

$$
|\Delta| \le 4
$$

because a chess move changes:

- source square,
- destination square,
- maybe one captured square distinct from destination (en passant),
- maybe rook source/destination (castling).

## 8. Certificate Refresh Rule

Only certificates whose observed squares may have changed are recomputed.

For each king $k_c$:

- if the king moved, recompute all $8$ ray certificates and all short-range certificates around the new king square;
- otherwise, for each $q \in \Delta$, if $q$ lies on a king ray from $k_c$, recompute only that one ray certificate;
- refresh knight/pawn certificates only if $q$ lies in the corresponding local origin set around $k_c$.

Since each changed square lies on at most one ray from a fixed king, a non-king move triggers at most $4$ ray refreshes per king, hence at most $8$ ray refreshes total.

Each refresh scans a line of length at most $7$.

Therefore the refresh cost is bounded by a small constant multiple of $8$, not $64$.

## 9. Formal Invariants

The state must satisfy:

### Invariant I1: King location soundness

$$
B(k_W) = wK, \qquad B(k_B) = bK.
$$

### Invariant I2: Ray soundness

For every $c,d$:

- if $\rho_1(c,d)=q\neq\bot$, then $q$ is the first occupied square on $\operatorname{Ray}(k_c,d)$,
- if $\rho_2(c,d)=r\neq\bot$, then $r$ is the second occupied square on that ray.

### Invariant I3: Local threat soundness

$\nu$ and $\pi$ match the board contents at the corresponding origin squares.

### Invariant I4: Check soundness

$$
\chi_c = 1 \iff k_c \text{ is attacked in } B.
$$

If these invariants hold before a move and the transition accepts, they also hold after the move.

## 10. Pseudocode

```text
function TRANSITION(S, W):
    input:
        S = (B, tau, kappa, ep, castle, rho, nu, pi, chi)
        W = (u, v, promo, aux)

    p := B[u]
    if p = empty: reject
    if color(p) != tau: reject
    if color(B[v]) = tau: reject

    if not GEOMETRY_OK(S, W, p): reject

    if is_slider(p):
        if not PATH_EMPTY(B, u, v): reject

    if is_castle(W):
        if not CASTLE_LOCAL_OK(S, W): reject

    if is_en_passant(W):
        if not EP_LOCAL_OK(S, W): reject

    if ABSOLUTELY_PINNED_AND_BREAKS_PIN(S, W, tau):
        reject

    S' := APPLY_LOCAL_BOARD_UPDATE(S, W)
    Delta := CHANGED_SQUARES(S, W)

    REFRESH_CERTIFICATES(S', Delta)

    if IN_CHECK(S', tau):
        reject

    return S'
```

### 10.1 Geometry Check

```text
function GEOMETRY_OK(S, W, p):
    switch piece_kind(p):
        pawn:
            return PAWN_GEOMETRY_OK(S, W, p)
        knight:
            return KNIGHT_STEP(u, v)
        bishop:
            return DIAGONAL(u, v)
        rook:
            return ORTHOGONAL(u, v)
        queen:
            return DIAGONAL(u, v) or ORTHOGONAL(u, v)
        king:
            return KING_STEP(u, v) or CASTLE_PATTERN(S, W)
```

### 10.2 Path Emptiness

```text
function PATH_EMPTY(B, u, v):
    (dir, len) := ray_descriptor(u, v)
    for t in 1 .. len - 1:
        if B[u + t*dir] != empty:
            return false
    return true
```

This touches at most $6$ interior squares.

### 10.3 Pin Test

```text
function ABSOLUTELY_PINNED_AND_BREAKS_PIN(S, W, c):
    u := W.from
    k := king_square(c)

    if u is not on any ray from k:
        return false

    d := direction_from(k, u)
    if rho1(c, d) != u:
        return false

    r := rho2(c, d)
    if r is not an enemy compatible slider:
        return false

    return not MOVE_STAYS_ON_PIN_RAY_AND_BETWEEN(k, r, W.to)
```

This is $O(1)$ using only $\rho_1,\rho_2$.

### 10.4 Certificate Refresh

```text
function REFRESH_CERTIFICATES(S, Delta):
    for c in {W, B}:
        k := king_square(c)

        if king of color c moved:
            for d in 8 directions:
                (rho1(c,d), rho2(c,d)) := FIRST_TWO_OCCUPIED_ON_RAY(B, k, d)
            for i in 1..8:
                nu(c,i) := board_at_knight_origin(B, k, i)
            for j in 1..2:
                pi(c,j) := board_at_pawn_origin(B, k, c, j)
        else:
            for each q in Delta:
                if q lies on a king ray from k:
                    d := direction_from(k, q)
                    (rho1(c,d), rho2(c,d)) := FIRST_TWO_OCCUPIED_ON_RAY(B, k, d)
            for i in 1..8:
                if knight_origin(k, i) in Delta:
                    nu(c,i) := board_at_knight_origin(B, k, i)
            for j in 1..2:
                if pawn_origin(k, c, j) in Delta:
                    pi(c,j) := board_at_pawn_origin(B, k, c, j)

        chi(c) := DERIVE_CHECK_BIT(S, c)
```

### 10.5 First-Two-Occupied on a Ray

```text
function FIRST_TWO_OCCUPIED_ON_RAY(B, k, d):
    first := bottom
    second := bottom

    for q in Ray(k, d):
        if B[q] != empty:
            if first = bottom:
                first := q
            else:
                second := q
                break

    return (first, second)
```

This scans at most $7$ squares.

## 11. Complexity Summary

Let $L \le 7$ be a maximal ray/path length.

For one transition:

1. Move geometry: $O(1)$.
2. Sliding path emptiness: $O(L)$.
3. Pin rejection: $O(1)$.
4. Certificate refresh:
   - non-king move: at most $8$ ray refreshes total, each $O(L)$,
   - king move: recompute all $8$ rays for the moved king, plus at most changed rays for the other king.
5. Check-bit derivation: $O(1)$.

Thus:

$$
\text{work}(T) = O(8L).
$$

Since $L \le 7$ on an $8 \times 8$ board,

$$
\text{work}(T) = O(8),
$$

with a board-size-independent constant for standard chess, and crucially no $O(64)$ full-board pass.

## 12. Why This Is Markov

The construction is Markov because all future legality information is encoded in the current state:

- board occupancy,
- side to move,
- castling rights,
- en-passant right,
- exact king positions,
- local king-centered certificates.

No historical replay is required.

The only history-sensitive chess rules are castling and en-passant, and those are fully summarized by $\mu$ and $\varepsilon$.

## 13. Minimal Variant

If one wants a smaller state, one may drop $\rho_2$ and keep only:

- board,
- side to move,
- castling rights,
- en-passant file,
- king squares,
- first-occupancy ray certificates,
- knight/pawn certificates,
- check bits.

This still permits $O(8)$ legality checking, but pin detection becomes slightly more expensive because it must inspect beyond the first blocker on demand.

So:

- with $\rho_2$: lower transition work,
- without $\rho_2$: smaller state.

## 14. Practical Interpretation

The core pattern is:

1. store the full legal board,
2. store exact king squares,
3. store only those summaries that matter for king safety,
4. update only summaries whose observation cones intersect the changed squares.

That is the formal reason the transition cost is governed by a constant number of king rays and local attack neighborhoods, not by all $64$ squares.
