"""Static analysis internals for the SAST engine (WP-D4).

Split out of `engines/sast_engine.py` because v2 is no longer a list of regexes: it is a small
data-flow analyser over Python's AST, a per-vulnerability-class sanitizer model, and a source
masker that stops comments and string literals from being reported as code.

The engine plugin remains the only thing the orchestrator sees. Nothing here imports the database,
the API, or the network.
"""

from guardian_scanner.sast.catalog import SANITIZERS, SINKS, Sink
from guardian_scanner.sast.masking import mask_non_code
from guardian_scanner.sast.taint import TaintFinding, analyze_python

__all__ = [
    "SANITIZERS",
    "SINKS",
    "Sink",
    "TaintFinding",
    "analyze_python",
    "mask_non_code",
]
