## Parallel Multiplexer Prototype

This is a minimal ICC-oriented prototype for a 3-script system:

- `mux.sil`: multiplexer, routes to `A` or `B`
- `A.sil`: worker path A, transitions state and routes back to `Mux`
- `B.sil`: worker path B, transitions state and routes back to `Mux`

All three contracts share the same state layout `S`.

The key experimental primitive is:

- `validateOutputStateWithTemplate(output_idx, new_state, template_prefix, template_suffix, expected_template_hash)`

The idea is:

1. store peer template hashes in state
2. provide a target template preimage split into prefix/suffix at spend time
3. verify the preimage against the stored hash
4. reinsert serialized state
5. verify the exact output script

This avoids inlining peer scripts into each other.
