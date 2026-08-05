"""EASM discovery subsystem (Phase 6B) — passive-first, plugin-based.

Pipeline (fixed order, providers plug into the front):

    provider.collect()  ->  normalize (canonicalize)  ->  identity resolve + dedup
                        ->  graph ingest (nodes + edges, lifecycle)  ->  asset intelligence

Only passive providers exist in 6B (DNS, CT). Active discovery (port/service scan) is 6C and stays
behind the authorization gate.
"""
