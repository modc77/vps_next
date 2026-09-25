from __future__ import annotations

from typing import Any


class WireError(ValueError):
    pass


def _varint(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            return value, pos
        shift += 7
        if shift > 70:
            raise WireError("varint too long")
    raise WireError("truncated varint")


def inspect_message(data: bytes, *, max_fields: int = 256) -> list[dict[str, Any]]:
    pos = 0
    result: list[dict[str, Any]] = []
    while pos < len(data) and len(result) < max_fields:
        tag, pos = _varint(data, pos)
        field = tag >> 3
        wire_type = tag & 7
        if field == 0:
            raise WireError("field number 0")
        item: dict[str, Any] = {"field": field, "wire_type": wire_type}
        if wire_type == 0:
            value, pos = _varint(data, pos)
            item["varint"] = value
        elif wire_type == 1:
            if pos + 8 > len(data):
                raise WireError("truncated fixed64")
            item["fixed64_len"] = 8
            pos += 8
        elif wire_type == 2:
            size, pos = _varint(data, pos)
            if pos + size > len(data):
                raise WireError("truncated length-delimited field")
            raw = data[pos:pos + size]
            pos += size
            item["length"] = size
            try:
                text = raw.decode("utf-8")
                if text.isprintable() and len(text) <= 128:
                    item["utf8"] = text
            except UnicodeDecodeError:
                pass
        elif wire_type == 5:
            if pos + 4 > len(data):
                raise WireError("truncated fixed32")
            item["fixed32_len"] = 4
            pos += 4
        else:
            raise WireError(f"unsupported wire type {wire_type}")
        result.append(item)
    return result
