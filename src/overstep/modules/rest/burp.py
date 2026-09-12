"""Burp Suite Pro XML HTTP history importer.

Reads a Burp Suite HTTP history export (XML), extracts each recorded request,
canonicalizes the path (replacing numeric segments with ``{id}`` and UUIDs with
``{uuid}``), deduplicates by ``(method, canonical_path)``, and emits a YAML
permission-matrix scaffold on stdout.

The scaffold has the same structure as a matrix produced by ``overstep scaffold``
from an OpenAPI file, so it can be pasted into a matrix file and annotated with
the real policy.

Usage (CLI integration via ``--burp-import FILE`` on the scaffold command, or
directly):

    from overstep.modules.rest.burp import burp_to_yaml
    print(burp_to_yaml("/path/to/burp-history.xml"))
"""
from __future__ import annotations

import base64
import re
from typing import Iterator, List, Optional, Tuple
from urllib.parse import urlparse
from xml.etree import ElementTree

import yaml

# Pattern matching a purely-numeric path segment (at least one digit, no alpha).
_NUMERIC_SEG = re.compile(r"^\d+$")
# Standard UUID in any case.
_UUID_SEG = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
# A long hex run that looks like an opaque id (16+ hex chars with no dashes).
_HEXLONG_SEG = re.compile(r"^[0-9a-fA-F]{16,}$")


def _canonicalize_path(path: str) -> str:
    """Replace id-like path segments with parameterized placeholders.

    Numeric segments become ``{id}``, UUID segments become ``{uuid}``.  Long
    hex runs (16+ chars) are treated the same as UUIDs.  Everything else is
    kept verbatim.
    """
    parts = path.split("/")
    out: List[str] = []
    for seg in parts:
        if not seg:
            out.append(seg)
        elif _UUID_SEG.match(seg) or _HEXLONG_SEG.match(seg):
            out.append("{uuid}")
        elif _NUMERIC_SEG.match(seg):
            out.append("{id}")
        else:
            out.append(seg)
    return "/".join(out)


def _resource_name(method: str, path: str) -> str:
    """Build a stable, human-readable resource name from a method + path."""
    slug = re.sub(r"[{}]", "", path).strip("/").replace("/", "_") or "root"
    return f"{method.lower()}_{slug}"


def _decode_base64_field(element: Optional[ElementTree.Element]) -> str:
    """Decode a Burp base64-encoded field element, returning empty string on failure."""
    if element is None:
        return ""
    is_b64 = (element.get("base64") or "").lower() == "true"
    raw = element.text or ""
    if not is_b64:
        return raw
    try:
        return base64.b64decode(raw).decode("utf-8", errors="replace")
    except Exception:
        return raw


def _iter_items(xml_path: str) -> Iterator[Tuple[str, str, str]]:
    """Yield ``(method, url, decoded_request)`` for each ``<item>`` in the file.

    The Burp XML schema places HTTP history entries under ``//items/item``.
    Fields of interest:
      - ``<method>``   — HTTP verb
      - ``<url>``      — full request URL
      - ``<request>``  — the raw HTTP request (may be base64-encoded)
    """
    try:
        tree = ElementTree.parse(xml_path)
    except ElementTree.ParseError as exc:
        raise ValueError(f"Burp XML file '{xml_path}' is not valid XML: {exc}") from exc

    root = tree.getroot()
    # The root element may be <items> directly, or the items may be nested.
    items = root.findall(".//item")
    if not items and root.tag == "item":
        items = [root]

    for item in items:
        method_el = item.find("method")
        url_el = item.find("url")
        request_el = item.find("request")

        method = (method_el.text or "GET").strip().upper() if method_el is not None else "GET"
        url = (url_el.text or "").strip() if url_el is not None else ""
        request_body = _decode_base64_field(request_el)

        yield method, url, request_body


def _parse_entries(xml_path: str) -> List[Tuple[str, str]]:
    """Return deduplicated ``(method, canonical_path)`` pairs from a Burp export."""
    seen: dict[Tuple[str, str], None] = {}
    for method, url, _request in _iter_items(xml_path):
        parsed = urlparse(url)
        raw_path = parsed.path or "/"
        canonical = _canonicalize_path(raw_path)
        key = (method, canonical)
        if key not in seen:
            seen[key] = None
    return list(seen.keys())


def burp_to_yaml(xml_path: str) -> str:
    """Parse a Burp history XML file and return a YAML permission-matrix scaffold.

    The scaffold lists all unique endpoints as ``resources``, includes two
    placeholder subjects (``subject_a`` and ``subject_b``), and adds stub
    ``policy`` entries — ready for the author to fill in role assignments and
    ``allow`` rules.
    """
    entries = _parse_entries(xml_path)

    resources = []
    policy: dict = {}
    for method, path in sorted(entries):
        name = _resource_name(method, path)
        has_id = "{id}" in path or "{uuid}" in path
        res: dict = {
            "name": name,
            "request": {"method": method, "path": path},
        }
        if has_id:
            res["type"] = "object"
            res["owner"] = "id" if "{id}" in path else "uuid"
        else:
            res["type"] = "function"
        resources.append(res)
        policy[name] = {
            "allow": [
                {"role": "REPLACE_ME_ROLE", "scope": "own" if has_id else "any"}
            ]
        }

    subjects = [
        {"name": "subject_a", "role": "REPLACE_ME_ROLE", "token": "PASTE_TOKEN_A"},
        {"name": "subject_b", "role": "REPLACE_ME_ROLE", "token": "PASTE_TOKEN_B"},
    ]

    matrix = {
        "roles": ["anonymous", "user", "admin"],
        "modules": {
            "rest": {
                "base_url": "PASTE_BASE_URL",
            }
        },
        "subjects": subjects,
        "resources": resources,
        "policy": policy,
    }

    header = (
        "# Scaffolded from Burp Suite HTTP history export.\n"
        "# Fill in PASTE_*/REPLACE_ME_* placeholders before running.\n"
        "#\n"
        f"# Endpoints imported: {len(entries)}\n"
        "#\n"
    )
    return header + yaml.dump(
        matrix,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
    )
