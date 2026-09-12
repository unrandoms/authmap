"""Price / quantity mutation probe (BOPLA — Business Object Property Level Abuse).

Detects fields whose value an API should protect against arbitrary mutation:
price, amount, total, quantity, discount, fee, credit and their common variants.
For every detected field, a set of boundary probe values is substituted in turn;
each modified request is sent and its response is compared to the baseline.  Any
2xx response whose body differs from the baseline is reported as a
``BOLA_PRICE_MANIPULATION`` finding.

Design constraints
------------------
* The probe is deliberately additive — it runs on top of a normal access-matrix
  run rather than replacing it, activated by ``--price-probe`` on the ``run``
  command.
* Only JSON bodies and ``application/x-www-form-urlencoded`` bodies are
  inspected; multipart/binary requests are left alone.
* Detection is field-name-based (case-insensitive) rather than value-based, so
  a field named ``discount`` with a string value is still probed.
* ``diff_body`` compares JSON responses structurally when possible, falling back
  to a plain text diff; it returns a human-readable summary of what changed.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib.parse import urlencode, urlparse

# Field names that indicate a monetarily- or quantity-sensitive value.
# Checked case-insensitively against every key in the request body.
PRICE_FIELD_NAMES = frozenset({
    "price",
    "amount",
    "total",
    "quantity",
    "discount",
    "fee",
    "credit",
})

# Boundary / edge-case values to substitute for each detected field.
PROBE_VALUES: List[Any] = [
    0,
    -1,
    -0.01,
    0.001,
    2147483647,
    9999999999,
    "0",
    "-1",
]

_PRICE_FIELD_RE = re.compile(
    r"\b(" + "|".join(re.escape(n) for n in PRICE_FIELD_NAMES) + r")\b",
    re.IGNORECASE,
)


@dataclass
class PriceFinding:
    """A single BOPLA price-manipulation finding."""

    resource_method: str
    resource_path: str
    subject: str
    field_name: str
    original_value: Any
    probe_value: Any
    response_status: int
    response_diff: str
    detail: str


def _is_price_field(name: str) -> bool:
    """True when *name* (case-insensitive) is a monitored price/quantity field."""
    return name.lower() in PRICE_FIELD_NAMES


def _extract_json_price_fields(body: Any, prefix: str = "") -> Iterator[Tuple[str, Any]]:
    """Recursively yield ``(dotted.path, value)`` for every price-like field in *body*.

    Only dicts and lists are descended into; scalars at the top level are
    ignored (a bare integer body has no field name to check).
    """
    if isinstance(body, dict):
        for key, value in body.items():
            path = f"{prefix}.{key}" if prefix else key
            if _is_price_field(key):
                yield path, value
            elif isinstance(value, (dict, list)):
                yield from _extract_json_price_fields(value, path)
    elif isinstance(body, list):
        for i, item in enumerate(body):
            yield from _extract_json_price_fields(item, f"{prefix}[{i}]")


def _extract_form_price_fields(form: Dict[str, Any]) -> Iterator[Tuple[str, Any]]:
    """Yield ``(key, value)`` for every price-like key in a form dict."""
    for key, value in form.items():
        if _is_price_field(key):
            yield key, value


def _set_nested(body: Any, dotted_path: str, value: Any) -> Any:
    """Return a deep copy of *body* with the field at *dotted_path* set to *value*.

    Path format: ``"a.b.c"`` for nested dicts, ``"a[0].b"`` for lists.
    Only dict and list containers are descended into.  If the path cannot be
    followed the body is returned unchanged.
    """
    import copy

    body = copy.deepcopy(body)
    parts = re.split(r"\.|(?=\[)", dotted_path)
    node: Any = body
    for part in parts[:-1]:
        if part.startswith("[") and part.endswith("]"):
            idx_str = part[1:-1]
            try:
                node = node[int(idx_str)]
            except (IndexError, TypeError, ValueError):
                return body
        else:
            if not isinstance(node, dict) or part not in node:
                return body
            node = node[part]
    last = parts[-1]
    if last.startswith("[") and last.endswith("]"):
        try:
            node[int(last[1:-1])] = value
        except (IndexError, TypeError, ValueError):
            pass
    elif isinstance(node, dict):
        node[last] = value
    return body


def _diff_bodies(baseline: str, modified: str) -> str:
    """Produce a compact diff summary between two response bodies.

    Attempts JSON structural comparison first; falls back to a plain-text
    line-level diff for non-JSON responses.
    """
    try:
        base_obj = json.loads(baseline)
        mod_obj = json.loads(modified)
        changed: List[str] = []
        _json_diff(base_obj, mod_obj, "", changed)
        if not changed:
            return "(no structural difference)"
        return "; ".join(changed[:10])
    except (json.JSONDecodeError, TypeError):
        pass

    # Plain-text line diff.
    base_lines = baseline.splitlines()
    mod_lines = modified.splitlines()
    added = [l for l in mod_lines if l not in base_lines]
    removed = [l for l in base_lines if l not in mod_lines]
    parts: List[str] = []
    if removed:
        parts.append(f"-{len(removed)} lines")
    if added:
        parts.append(f"+{len(added)} lines")
    return " / ".join(parts) if parts else "(no difference)"


def _json_diff(a: Any, b: Any, path: str, out: List[str]) -> None:
    """Recursively collect changed paths between two JSON values."""
    if type(a) is not type(b):
        out.append(f"{path or 'root'}: {a!r} -> {b!r}")
        return
    if isinstance(a, dict):
        all_keys = set(a) | set(b)
        for key in sorted(all_keys):
            child_path = f"{path}.{key}" if path else key
            if key not in a:
                out.append(f"+{child_path}: {b[key]!r}")
            elif key not in b:
                out.append(f"-{child_path}: {a[key]!r}")
            else:
                _json_diff(a[key], b[key], child_path, out)
    elif isinstance(a, list):
        for i, (ai, bi) in enumerate(zip(a, b)):
            _json_diff(ai, bi, f"{path}[{i}]", out)
        if len(a) != len(b):
            out.append(f"{path}: length {len(a)} -> {len(b)}")
    else:
        if a != b:
            out.append(f"{path or 'root'}: {a!r} -> {b!r}")


# ---------------------------------------------------------------------------
# Synchronous runner
# ---------------------------------------------------------------------------

def run_price_probe(
    base_url: str,
    method: str,
    path: str,
    headers: Dict[str, str],
    json_body: Optional[Any] = None,
    form_body: Optional[Dict[str, Any]] = None,
    subject_name: str = "",
    *,
    verify_tls: bool = True,
    timeout: float = 15.0,
) -> List[PriceFinding]:
    """Probe one endpoint for price/quantity manipulation.

    Fires the baseline request first, then sends a probe request for each
    (field, probe_value) combination where a price-like field is detected.
    Returns a finding for every 2xx probe response whose body differs from the
    baseline.
    """
    import asyncio
    return asyncio.run(
        _async_price_probe(
            base_url,
            method,
            path,
            headers,
            json_body=json_body,
            form_body=form_body,
            subject_name=subject_name,
            verify_tls=verify_tls,
            timeout=timeout,
        )
    )


async def _async_price_probe(
    base_url: str,
    method: str,
    path: str,
    headers: Dict[str, str],
    json_body: Optional[Any] = None,
    form_body: Optional[Dict[str, Any]] = None,
    subject_name: str = "",
    *,
    verify_tls: bool = True,
    timeout: float = 15.0,
) -> List[PriceFinding]:
    try:
        import httpx
    except ImportError as exc:
        raise ImportError("httpx is required for price probing") from exc

    from urllib.parse import urljoin

    url = urljoin(
        base_url if base_url.endswith("/") else base_url + "/",
        path.lstrip("/"),
    )

    findings: List[PriceFinding] = []

    async with httpx.AsyncClient(
        timeout=timeout, verify=verify_tls, follow_redirects=False
    ) as client:
        # 1. Baseline request.
        try:
            if form_body is not None:
                baseline_resp = await client.request(
                    method, url, headers=headers, data=form_body
                )
            else:
                baseline_resp = await client.request(
                    method, url, headers=headers, json=json_body
                )
        except Exception:
            # Network error on baseline — nothing to compare against.
            return []

        baseline_body = baseline_resp.text

        # 2. Identify price-like fields in the request.
        price_fields: List[Tuple[str, Any, bool]] = []  # (path, original_value, is_form)
        if form_body is not None:
            for fname, fval in _extract_form_price_fields(form_body):
                price_fields.append((fname, fval, True))
        elif json_body is not None:
            for fpath, fval in _extract_json_price_fields(json_body):
                price_fields.append((fpath, fval, False))

        if not price_fields:
            return []

        # 3. For each price field + probe value, send a modified request.
        for field_path, original_value, is_form in price_fields:
            for probe_value in PROBE_VALUES:
                try:
                    if is_form:
                        modified_form = dict(form_body)  # type: ignore[arg-type]
                        modified_form[field_path] = probe_value
                        probe_resp = await client.request(
                            method, url, headers=headers, data=modified_form
                        )
                    else:
                        modified_body = _set_nested(json_body, field_path, probe_value)
                        probe_resp = await client.request(
                            method, url, headers=headers, json=modified_body
                        )
                except Exception:
                    continue

                is_2xx = 200 <= probe_resp.status_code < 300
                if not is_2xx:
                    continue

                probe_body = probe_resp.text
                if probe_body == baseline_body:
                    # Same response body — server likely ignored the mutation.
                    continue

                diff_summary = _diff_bodies(baseline_body, probe_body)
                # Leaf name for reporting (strip dotted prefix).
                leaf = field_path.split(".")[-1].lstrip("[").rstrip("]")
                findings.append(
                    PriceFinding(
                        resource_method=method,
                        resource_path=path,
                        subject=subject_name,
                        field_name=leaf,
                        original_value=original_value,
                        probe_value=probe_value,
                        response_status=probe_resp.status_code,
                        response_diff=diff_summary,
                        detail=(
                            f"BOPLA_PRICE_MANIPULATION: field '{leaf}' accepted "
                            f"probe value {probe_value!r} (original: {original_value!r}); "
                            f"response body changed: {diff_summary}"
                        ),
                    )
                )

    return findings
