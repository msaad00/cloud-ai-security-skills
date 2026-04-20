"""Function 2 — Worker: execute the 11-step Entra IAM teardown for one user.

Receives validated entries from the parser Function via the Logic App map
step. Each entry runs through the eleven steps defined in
:mod:`steps`, with dual audit (Cosmos DB + CMK-encrypted Blob Storage)
before and after every step.
"""
