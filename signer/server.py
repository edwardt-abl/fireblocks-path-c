#!/usr/bin/env python3
"""
Mind Relay Signing Service for Path C.

Holds MIND_RELAY_PRIVATE_KEY (Ed25519, base64). When the Mind needs to sign a
command envelope, it POSTs the unsigned intent here and receives the signed
envelope back. The executor verifies the signature with MIND_RELAY_PUBLIC_KEY.

HARD RULE: This service holds the Mind's signing key. Authentication is by
bearer token. Do not run without HTTPS (terminate TLS upstream) and do not
expose to the public internet.
"""

import base64
import hashlib
import json
import os
import time
import uuid

from fastapi import FastAPI, Header, HTTPException
from nacl.signing import SigningKey
from pydantic import BaseModel

app = FastAPI(title="mind-relay-signer", version="1.0.0")

# Load config at startup; fail closed if missing.
SIGNING_KEY_B64 = os.environ.get("MIND_RELAY_PRIVATE_KEY", "")
EXPECTED_BEARER = os.environ.get("MIND_SIGNER_BEARER", "")
REPLAY_WINDOW_SEC = int(os.environ.get("ENVELOPE_REPLAY_WINDOW_SEC", "300"))

if not SIGNING_KEY_B64:
    raise RuntimeError("MIND_RELAY_PRIVATE_KEY is required (base64 Ed25519 secret key)")
if not EXPECTED_BEARER:
    raise RuntimeError("MIND_SIGNER_BEARER is required")

SIGNING_KEY = SigningKey(base64.b64decode(SIGNING_KEY_B64))


class IntentPayload(BaseModel):
    intentId: str
    operatorId: str
    conversationId: str
    sourceVaultId: str
    assetId: str
    destinationAddress: str
    amount: str
    note: str | None
    payloadHash: str


class SignRequest(BaseModel):
    intent: IntentPayload


class SignedEnvelope(BaseModel):
    signature: str
    intent: dict
    timestamp: int
    nonce: str


def _canonical_bytes(intent: dict) -> bytes:
    """Canonical JSON: sorted keys, no whitespace. Must match executor's canonicalizeIntent."""
    return json.dumps(
        {k: intent[k] for k in sorted(intent.keys())},
        separators=(",", ":"),
    ).encode("utf-8")


@app.post("/sign", response_model=SignedEnvelope)
def sign(
    req: SignRequest,
    authorization: str | None = Header(default=None),
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing_bearer")
    token = authorization[len("Bearer "):]
    if token != EXPECTED_BEARER:
        raise HTTPException(status_code=401, detail="invalid_bearer")

    intent_dict = req.intent.dict()
    canonical = _canonical_bytes(intent_dict)

    signed = SIGNING_KEY.sign(canonical)
    signature_b64 = base64.b64encode(signed.signature).decode("ascii")

    return SignedEnvelope(
        signature=signature_b64,
        intent=intent_dict,
        timestamp=int(time.time()),
        nonce=str(uuid.uuid4()),
    )


@app.get("/health")
def health():
    # Don't echo the public key fingerprint here — that would aid reconnaissance.
    return {"status": "ok", "ts": int(time.time())}