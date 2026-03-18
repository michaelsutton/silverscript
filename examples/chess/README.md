# Chess Example

This folder is a standalone Cargo workspace for the mux/worker on-chain chess covenant demo.

## Core Idea

This example applies the multiplexer pattern to chess.

Instead of one giant contract that tries to enforce the whole game at once, the
protocol is split into:

- `ChessMux`: the durable checkpoint contract that owns the full game state
- worker contracts: narrow validators for bounded move families and challenge flows

All of these contracts share the same serialized state layout.

The key primitive is still the mux pattern itself:

1. mux authenticates the move attempt
2. mux commits the pending move into shared state
3. mux routes into the selected worker template
4. the worker proves one bounded claim
5. the worker returns to mux with updated state

The important design philosophy is bounded verification rather than eager global
analysis. The protocol prefers proving a narrow local claim now and using
challenge paths for rules that are easier to refute than to prove by sweeping
the full board.

Layout:

- `chess-covenant/`: Rust crate with compile-time tests for the covenant source.
- `sil/`: SilverScript source files for the active mux and worker contracts.
- `ARCHITECTURE.md`: high-level design principles for the mux/worker chess protocol.

## TODO

This list is kept up to date. Completed, descoped, or split items are reflected
here in the same change that updates their status.

### Protocol

- [ ] Add rare draw rules such as repetition and the 50-move rule.
- [ ] Make sure all classical game rules can be fully enforced by the opponent through the protocol, and verify that no rule or challenge path is missing.
- [ ] Tighten all draw and termination rules until the full settlement logic is robust enough for production use.
- [ ] Tighten the logic of blitz chess and make sure all supported time-control modes still preserve challenge/timeout liveness, including non-blitz modes where there is no per-turn clock.

### Funds And Settlement

- [ ] Allow the game to begin from a mutual KAS deposit into the initial contract state.
- [ ] Allow the winner to claim the KAS and terminate the contract after winning.
- [ ] On draw, allow a split withdrawal path.

### Off-Chain Enforcement

- [ ] Implement an off-chain Rust wrapper for the on-chain logic so a player can enforce classical rules by challenging and proving wrong behavior.
- [ ] Base that wrapper on a well-established Rust chess crate as the main rules engine and source of truth.
- [ ] Import a strong chess benchmark or test suite with many complex games and verify them against this protocol.
- [ ] Build an adversarial opponent, or equivalent configurable wrapper modes, that tries to cheat and confirm that an honest player can always enforce their rights.

### Runtime

- [ ] Build a runtime for playing the game over Kaspa Testnet 12, starting with a console interface if that is the fastest path.

### Documentation And Book

- [ ] End this project with a full md book that explains the mux pattern, its subtle points, and the overall philosophy behind this chess system.
- [ ] Use the book to show how complex distributed systems can be built directly on native pure Kaspa L1 after covenant support.
- [ ] Make the chess challenge theme a central teaching device for bounded verification: prove a narrow claim, avoid full sweeps, and push the reader toward NP-like protocol thinking instead of eager global recomputation.
- [ ] Write the book for advanced builders and agents, so it does not just document this project but also transfers the design mindset needed to build similar systems.

### Mid Term

- [ ] Build full chess server logic with persistent player scoring based on game results.
- [ ] Define the outer covenant and game-entry/settlement protocol needed to represent and update those scores on chain.
