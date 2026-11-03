#!/usr/bin/env python3
"""Shows that malformed and future-schema records are refused, not guessed at.

An inventory's whole value is completeness, so a record it cannot read must be
an error. Silently skipping one would under-report the inventory while still
calling it complete, which is the single worst thing this mechanism could do.
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import read as reader  # noqa: E402

PAYLOAD = b'{"id":"x::y","module":"x","function":"y"}'

CASES = [
    ("a well-formed record", reader.MAGIC + struct.pack("<HI", 1, len(PAYLOAD)) + PAYLOAD),
    (
        "a length past the section end",
        reader.MAGIC + struct.pack("<HI", 1, len(PAYLOAD) + 500) + PAYLOAD,
    ),
    (
        "an unknown schema version",
        reader.MAGIC + struct.pack("<HI", 99, len(PAYLOAD)) + PAYLOAD,
    ),
    ("a truncated header", reader.MAGIC + b"\x01"),
    (
        "payload that is not JSON",
        reader.MAGIC + struct.pack("<HI", 1, 5) + b"{{{{{",
    ),
]

for label, blob in CASES:
    try:
        found = list(reader.records(blob))
        print(f"  {label:32s} -> accepted: {found[0]['id']}")
    except Exception as error:  # noqa: BLE001 - every failure mode is reportable
        print(f"  {label:32s} -> refused: {error}")
