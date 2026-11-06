"""Payload search: find canary values inside captured network payloads.

A canary value can leave the sandbox in several shapes, so every captured
blob (URL, header block, body) is searched in layers:

1. direct forms of the value itself: raw bytes, base64 (with and without
   padding), hex, and URL-encoded;
2. decoded forms: base64-looking tokens inside the blob are decoded and
   the decoded bytes are searched raw (this catches a whole file that was
   base64-encoded before sending, where base64(value) never appears as a
   substring); hex-looking tokens are decoded the same way; the blob is
   also percent-decoded and searched raw.

Each hit reports the canary type and the encoding layer that matched.
"""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse

_B64_TOKEN = re.compile(rb"[A-Za-z0-9+/=_-]{16,}")
_HEX_TOKEN = re.compile(rb"[0-9a-fA-F]{32,}")


def value_forms(value):
    """Return {encoding: bytes} for the direct encodings of one value."""
    raw = value.encode("utf-8")
    b64 = base64.b64encode(raw)
    return {
        "raw": raw,
        "base64": b64,
        "base64_nopad": b64.rstrip(b"="),
        "hex": binascii.hexlify(raw),
        "urlencoded": urllib.parse.quote_from_bytes(raw, safe="").encode("ascii"),
    }


def _try_b64_decode(token):
    token = token.strip()
    # Translate URL-safe alphabet, then require a plausible length.
    token = token.replace(b"-", b"+").replace(b"_", b"/")
    if len(token) % 4 == 1:
        return None
    padded = token + b"=" * (-len(token) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None


def _b64_decode_attempts(token):
    """Decode a candidate token, tolerating transport junk stuck to its
    front: a query assignment (``d=<b64>``) makes the key part of the
    regex token, and an interior '=' then breaks strict decoding. Try
    the token as-is, the part after a short ``key=`` prefix, and small
    leading trims."""
    attempts = [token]
    head, sep, rest = token.partition(b"=")
    if sep and rest and len(head) <= 4:
        attempts.append(rest)
    for drop in (1, 2, 3):
        if len(token) > drop + 8:
            attempts.append(token[drop:])
    seen = set()
    for attempt in attempts:
        if attempt in seen:
            continue
        seen.add(attempt)
        decoded = _try_b64_decode(attempt)
        if decoded:
            yield decoded


def _decoded_variants(data):
    """Yield (encoding, bytes) for decodings of tokens found in data."""
    seen = set()
    for match in _B64_TOKEN.finditer(data):
        token = match.group(0)
        if token in seen:
            continue
        seen.add(token)
        for decoded in _b64_decode_attempts(token):
            yield "base64", decoded
    for match in _HEX_TOKEN.finditer(data):
        token = match.group(0)
        if len(token) % 2:
            continue
        try:
            decoded = binascii.unhexlify(token)
        except (binascii.Error, ValueError):
            continue
        yield "hex", decoded
    unquoted = urllib.parse.unquote_to_bytes(data.decode("utf-8", "replace"))
    if unquoted != data:
        yield "urlencoded", unquoted


def search_blob(data, values):
    """Search bytes for canary values.

    values: {canary_type: [value, ...]}
    Returns a list of hits: {"canary_type", "encoding", "value_index"}.
    At most one hit per (canary_type, encoding) pair.

    The search is a small breadth-first walk: the blob itself is scanned
    for the direct encodings of every value, then decoded variants of
    the blob (base64 / hex token decodings, percent-decoding) are
    scanned the same way, up to two decode layers deep - so a value
    inside base64(file) that was itself URL-encoded into a query string
    is still found, and is attributed to the deepest decode layer.
    """
    if not data:
        return []
    hits = {}
    prepared = {
        ctype: [(idx, value_forms(v)) for idx, v in enumerate(vals)]
        for ctype, vals in values.items()
    }

    def scan_direct(blob, via_encoding):
        for ctype, entries in prepared.items():
            for idx, forms in entries:
                for enc, needle in forms.items():
                    if needle and needle in blob:
                        label = via_encoding or enc
                        key = (ctype, label)
                        if key not in hits:
                            hits[key] = {
                                "canary_type": ctype,
                                "encoding": label,
                                "value_index": idx,
                            }
                        break  # one hit per (canary, value) per blob layer

    frontier = [(data, None)]
    for depth in range(3):
        next_frontier = []
        for blob, via in frontier:
            scan_direct(blob, via)
            if depth < 2:
                for enc, decoded in _decoded_variants(blob):
                    next_frontier.append((decoded, enc))
        frontier = next_frontier
    return list(hits.values())
