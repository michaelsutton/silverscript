# State Decoder Metadata Proposal

## Goal

Define a minimal compiler-emitted metadata surface that lets an external decoder recover and
verify authored covenant state transitions from:

- the compiled contract
- the spending transaction, populated with input UTXO entries

The decoder should execute the real script, stop at compiler-recorded bytecode offsets, read raw
VM stack values, and independently verify the authored output against the transaction itself.

The compiler metadata is therefore a navigation aid, not a source of truth.

*The intended consumer is a general-purpose indexer that only needs prior knowledge of covenant
ids and compiled contracts, and can then decode any transaction that follows the SilverScript
compiler conventions and belongs to a known covenant / compiled contract set.*

## Scope

Initial scope covers:

- `validateOutputState(output_idx, state)`
- `validateOutputStateWithTemplate(output_idx, state, template_prefix, template_suffix, expected_template_hash)`

This document is intentionally focused on outputs for now. Input-state decoding is more flexible,
since it can often be recovered directly from the per-input sigscript, whereas output state may
only be explicitly present around specific execution points.

## Data Assumptions

The decoder should assume it has:

- the full spending transaction (populated with input UTXO entries)
- the active input sigscript
- the full executed locking script / redeem script

This should be the default model for a general decoder.

## External Surface

The compiler should attach state-decoder metadata to the compiled contract object and
serialized JSON output, alongside existing data such as `state_subrange`.

Proposed JSON shape:

```json
{
  "state_decoder": {
    "state_layouts": [
      {
        "fields": [
          { "name": "amount", "type_name": "int" },
          { "name": "code", "type_name": "byte[2]" }
        ]
      }
    ],
    "validation_calls": [
      {
        "builtin_kind": "validateOutputState",
        "captures": [
          {
            "field": "encodedState",
            "bytecode_offset": 123,
            "state_layout_id": 0
          },
          {
            "field": "outputIdx",
            "bytecode_offset": 211
          }
        ]
      }
    ]
  }
}
```

Where:

- `builtin_kind` identifies the builtin lowering scheme the decoder should apply
- `captures` are listed in bytecode order
- each capture points to a bytecode offset where the needed value is on top of stack
- `state_layout_id` is present only for `encodedState`
- `state_layouts[0]` should always describe the local contract `State` object

In addition, the compiled contract should expose its own `state_subrange`:

```text
state_subrange = { start, end }
```

This lets a decoder extract the contract bytes around the state payload and derive:

- `prefix`
- `suffix`
- template hash

for any given contract.

## Required Contract Surface

The compiled contract object should expose two layout-facing functions:

```text
decode_state(state_layout_id, bytes)
  -> HashMap<String, (String, bytes)>

get_layout(state_layout_id)
  -> HashMap<String, (String, LayoutSubrange)>
```

Meaning:

- `decode_state(...)` returns a map from field name to:
  - declared `type_name`
  - raw field bytes

- `get_layout(...)` returns a map from field name to:
  - declared `type_name`
  - `LayoutSubrange` describing where that field sits inside the encoded state blob

This keeps the external decoder surface small while still allowing clients to:

- inspect raw decoded field bytes
- implement their own type decoding if desired
- reconstruct layout slices without trusting compiler-produced final values

## Capture Semantics

The compiler records offsets for the moment the required argument is on top of stack.

Current captured fields:

- `validateOutputState`
  - `encodedState`
  - `outputIdx`

- `validateOutputStateWithTemplate`
  - `expectedTemplateHash`
  - `encodedState`
  - `outputIdx`

This is intentionally not a "full builtin snapshot" scheme. The decoder records only the fields
it actually needs to reconstruct and verify the authored output.

## Decoder Model

Given:

- a compiled contract
- a spending transaction populated with input UTXO entries
- the active input sigscript and executed locking script

the decoder:

1. Executes the real script.
2. Stops at the recorded capture offsets.
3. Reads the top-of-stack payload at each capture point.
4. Uses `decode_state(...)` / `get_layout(...)` for `encodedState`.
5. Reconstructs the expected authored output independently.
6. Verifies it against `tx.outputs[outputIdx]`.

### `validateOutputState`

For `validateOutputState`, the executing contract already determines the active template family.

So the decoder only needs:

- `encodedState`
- `outputIdx`

From there it can rebuild the expected authored contract for the current family and verify it
against the selected output.

### `validateOutputStateWithTemplate`

For `validateOutputStateWithTemplate`, the decoder needs:

- `expectedTemplateHash`
- `encodedState`
- `outputIdx`

The decoder uses `expectedTemplateHash` as the hint that points it at the target contract.
Once the target contract is known, the decoder already knows its template prefix/suffix, so it can
independently rebuild:

- `template_prefix || encodedState || template_suffix`
- hash it
- wrap it to P2SH
- compare the resulting scriptPubKey to `tx.outputs[outputIdx]`

In other words, the compiler does not need to provide template prefix/suffix as captured values.
The template hash is sufficient.

## Trust Assumptions

The trust model is intentionally strict:

- the compiler provides offsets, builtin kinds, and state layout references
- the decoder does not trust compiler-emitted final state conclusions
- all recovered states must eventually verify against the transaction and its tx id

If execution or verification disagrees with the transaction, the decoder should fail closed rather
than accepting compiler metadata as authoritative.
