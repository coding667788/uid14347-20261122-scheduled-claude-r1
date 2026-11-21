"""Fictional two-stage challenge ledger.

Pure standard-library, CPU-only reference implementation for a made-up
internal authentication system.  Nothing in this package performs real
cryptography or talks to a network: every subject, challenge and proof is a
synthetic identifier and every trust signal is a boolean.
"""

__version__ = "1.0.0"
SCHEMA = "challenge-ledger/v1"

# `SCHEMA_NAME` in ledger.ledger is the same wire constant; it is defined once
# there and re-exported here so both names cannot drift apart.
SCHEMA_NAME = SCHEMA

__all__ = ["SCHEMA", "SCHEMA_NAME", "__version__"]
