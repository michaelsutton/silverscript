# Chess Covenant Notes

This mdBook is currently a design notebook for the outer league / player / game
layer.

The immediate goal is clarity:

- which contracts depend on which other templates
- which hashes must be injected into state
- how settlement auth is intended to flow

All diagrams assume the current preferred outer design:

- one shared covenant id across league, player, and game
- different contracts carry the role identity
- role validation therefore needs input-template primitives plus injected hashes

