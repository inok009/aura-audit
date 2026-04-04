"""
JSON Formatter — ASFF-inspired output serializer.
Outputs newline-delimited JSON (NDJSON) for jq compatibility,
or a single JSON array with --format array.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Literal

from ..schemas.finding import Finding


class JSONFormatter:

    def __init__(
        self,
        format: Literal["ndjson", "array"] = "array",
        output: str | None = None,   # None → STDOUT
        min_severity: str = "INFORMATIONAL",
    ) -> None:
        self._format = format
        self._output_path = Path(output) if output else None
        self._severity_order = [
            "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"
        ]
        self._min_idx = self._severity_order.index(min_severity.upper())

    def serialize(self, findings: list[Finding]) -> str:
        filtered = [
            f for f in findings
            if self._severity_order.index(f.severity.value) <= self._min_idx
        ]
        # Sort: CRITICAL first
        filtered.sort(
            key=lambda f: self._severity_order.index(f.severity.value)
        )

        records = [f.model_dump() for f in filtered]

        if self._format == "ndjson":
            output = "\n".join(json.dumps(r) for r in records)
        else:
            output = json.dumps(
                {
                    "schema": "aura-audit/v1",
                    "total_findings": len(records),
                    "findings": records,
                },
                indent=2,
            )

        if self._output_path:
            self._output_path.write_text(output, encoding="utf-8")
        else:
            sys.stdout.write(output + "\n")

        return output