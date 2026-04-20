"""Function 1 — Parser: validate + filter the Blob Storage manifest.

Triggered by the Logic App after EventGrid detects a new blob in the
`departures/` prefix of the manifest container. This package wraps a single
`handler.py` that mirrors the role of the AWS sibling's `lambda_parser`.
"""
