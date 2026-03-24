## Multiplexer Prototype

This is a minimal ICC-oriented prototype for a 3-script system:

- `mux.sil`: the entry lane multiplexer; routes to `A` or `B`
- `A.sil`: worker path A; updates state and returns to `Mux`
- `B.sil`: worker path B; updates state and returns to `Mux`

All three contracts share the same state layout `S`, so the system can move the same logical state across different contract templates.

The full round-trip is:

1. spend `Mux`
2. route to worker `A` or `B`
3. let that worker update shared state
4. return to `Mux`

The key experimental primitive is:

- `validateOutputStateWithTemplate(output_idx, new_state, template_prefix, template_suffix, expected_template)`

The idea is:

1. store peer templates in state
2. provide a target template preimage split into prefix/suffix at spend time
3. verify the preimage against the stored template
4. reinsert serialized state
5. verify the exact output script

This avoids inlining peer scripts into each other.
