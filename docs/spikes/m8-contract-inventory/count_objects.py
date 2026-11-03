#!/usr/bin/env python3
"""Counts the object members of an `ar` archive."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import read as reader  # noqa: E402

archive = open(sys.argv[1], "rb").read()
print(sum(1 for name, _ in reader.ar_members(archive) if name.endswith(".o")))
