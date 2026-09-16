"""Host/network posture assessed from an authorized local agent's allowlisted submission.

A cloud server cannot reach a user's private LAN or their authenticated host, so this is NOT
cloud-to-LAN scanning. An agent the user installs collects an allowlisted, non-destructive posture
report and submits it; the platform assesses that report. Collection authorization lives at the
agent; this package only normalizes and evaluates what was submitted.
"""
