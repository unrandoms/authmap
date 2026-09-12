"""JWT identity-swap IDOR module.

Decodes two JWT tokens (no signature verification), extracts identity claims
from both, builds probe tokens by swapping user A's claim values with user B's,
and optionally builds an alg:none probe.  The resulting tokens are used to drive
the existing REST access-matrix executor.
"""
