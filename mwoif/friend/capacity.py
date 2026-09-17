from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any


_PLAYER_ID_RE = re.compile(r"^[A-Z0-9]{7,16}$")


class ProtoScanError(ValueError):
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
            raise ProtoScanError("varint too long")
    raise ProtoScanError("truncated varint")


def _looks_like_player_id(text: str) -> bool:
    value = str(text or "").strip()
    if not _PLAYER_ID_RE.fullmatch(value):
        return False
    # Runtime player ids seen by the project contain both letters and digits.
    return any(c.isalpha() for c in value) and any(c.isdigit() for c in value)


def _scan_message(
    data: bytes,
    *,
    path: tuple[int, ...] = (),
    depth: int = 0,
    max_depth: int = 6,
    max_fields: int = 5000,
) -> list[tuple[tuple[int, ...], str]]:
    """Recursively collect printable protobuf strings with field paths.

    ListFriends has no generated Python protobuf class in this project.  This
    scanner intentionally does not assume a response schema.  The capacity
    parser later chooses the repeated path whose values have the same shape as
    the game player ids already observed by the project.
    """
    pos = 0
    seen = 0
    out: list[tuple[tuple[int, ...], str]] = []
    while pos < len(data) and seen < max_fields:
        seen += 1
        tag, pos = _varint(data, pos)
        field = tag >> 3
        wire_type = tag & 7
        if field <= 0:
            raise ProtoScanError("invalid protobuf field")
        field_path = path + (field,)

        if wire_type == 0:
            _value, pos = _varint(data, pos)
        elif wire_type == 1:
            if pos + 8 > len(data):
                raise ProtoScanError("truncated fixed64")
            pos += 8
        elif wire_type == 2:
            size, pos = _varint(data, pos)
            if size < 0 or pos + size > len(data):
                raise ProtoScanError("truncated length-delimited field")
            raw = data[pos:pos + size]
            pos += size

            try:
                text = raw.decode("utf-8")
                if text and text.isprintable() and len(text) <= 256:
                    out.append((field_path, text))
            except UnicodeDecodeError:
                pass

            # Embedded protobuf messages are also length-delimited.  Try a
            # recursive decode but treat failure as ordinary bytes/string.
            if depth < max_depth and raw:
                try:
                    nested = _scan_message(
                        raw,
                        path=field_path,
                        depth=depth + 1,
                        max_depth=max_depth,
                        max_fields=max_fields,
                    )
                    out.extend(nested)
                except Exception:
                    pass
        elif wire_type == 5:
            if pos + 4 > len(data):
                raise ProtoScanError("truncated fixed32")
            pos += 4
        else:
            raise ProtoScanError(f"unsupported protobuf wire type {wire_type}")
    return out


@dataclass(frozen=True, slots=True)
class FriendCapacity:
    friend_count: int
    friend_player_ids: tuple[str, ...]
    capacity: int
    free_slots: int
    parser_confidence: str
    selected_path: tuple[int, ...] | None
    candidate_group_count: int
    raw_bytes: int
    candidate_groups: tuple[tuple[tuple[int, ...], tuple[str, ...]], ...] = ()

    def public_dict(self) -> dict[str, Any]:
        return {
            "friend_count": self.friend_count,
            "capacity": self.capacity,
            "free_slots": self.free_slots,
            "parser_confidence": self.parser_confidence,
            "player_ids_available": len(self.friend_player_ids),
            "selected_path": list(self.selected_path or ()),
            "candidate_group_count": self.candidate_group_count,
            "response_bytes": self.raw_bytes,
            "secretOutput": "NONE",
        }

    def relationship_groups(self) -> tuple[tuple[tuple[int, ...], tuple[str, ...]], ...]:
        return self.candidate_groups


def parse_friend_list_response(raw: bytes, *, capacity: int = 300) -> FriendCapacity:
    capacity = max(1, int(capacity))
    if not raw:
        return FriendCapacity(
            friend_count=0,
            friend_player_ids=(),
            capacity=capacity,
            free_slots=capacity,
            parser_confidence="high",
            selected_path=None,
            candidate_group_count=0,
            raw_bytes=0,
            candidate_groups=(),
        )

    strings = _scan_message(raw)
    groups: dict[tuple[int, ...], list[str]] = defaultdict(list)
    for path, text in strings:
        value = text.strip()
        if _looks_like_player_id(value):
            groups[path].append(value)

    scored: list[tuple[int, int, tuple[int, ...], tuple[str, ...]]] = []
    for path, values in groups.items():
        unique = tuple(dict.fromkeys(values))
        count = len(unique)
        if not count or count > capacity:
            continue
        scored.append((count, len(path), path, unique))

    if not scored:
        return FriendCapacity(
            friend_count=0,
            friend_player_ids=(),
            capacity=capacity,
            free_slots=capacity,
            parser_confidence="none",
            selected_path=None,
            candidate_group_count=len(groups),
            raw_bytes=len(raw),
            candidate_groups=(),
        )

    scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
    count, _depth, path, ids = scored[0]
    confidence = "high" if count >= 2 else "medium"
    relationship_groups = tuple((item[2], item[3]) for item in scored)
    return FriendCapacity(
        friend_count=count,
        friend_player_ids=ids,
        capacity=capacity,
        free_slots=max(0, capacity - count),
        parser_confidence=confidence,
        selected_path=path,
        candidate_group_count=len(scored),
        raw_bytes=len(raw),
        candidate_groups=relationship_groups,
    )
