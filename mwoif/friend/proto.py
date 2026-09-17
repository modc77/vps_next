from __future__ import annotations


class FriendProtoError(ValueError):
    pass


def encode_varint(value: int) -> bytes:
    if value < 0:
        raise FriendProtoError("varint must be >= 0")
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def encode_string(field_number: int, value: str) -> bytes:
    raw = value.encode("utf-8")
    return encode_varint((field_number << 3) | 2) + encode_varint(len(raw)) + raw


def encode_bool(field_number: int, value: bool) -> bytes:
    if not value:
        return b""
    return encode_varint((field_number << 3) | 0) + b"\x01"


def encode_uint(field_number: int, value: int) -> bytes:
    if value == 0:
        return b""
    return encode_varint((field_number << 3) | 0) + encode_varint(value)


def build_send_friend_request(player_id: str, source_type: int) -> bytes:
    """V1-pass wire shape: field #2 = target player_id, field #3 = source_type."""
    player_id = player_id.strip()
    if not player_id:
        raise FriendProtoError("player_id is required")
    if source_type not in (1, 2, 3, 4):
        raise FriendProtoError("source_type must be one of 1,2,3,4")
    return encode_string(2, player_id) + encode_uint(3, source_type)


def build_handle_friend_request(player_id: str, accept: bool) -> bytes:
    """V1-pass wire shape: field #2 = target player_id, field #3 = accept bool."""
    player_id = player_id.strip()
    if not player_id:
        raise FriendProtoError("player_id is required")
    return encode_string(2, player_id) + encode_bool(3, accept)


def build_remove_friend_request(player_ids: list[str] | tuple[str, ...]) -> bytes:
    """V1-pass wire shape: field #2 = repeated player_id string."""
    cleaned: list[str] = []
    seen: set[str] = set()
    for raw in player_ids:
        player_id = str(raw or "").strip()
        if not player_id:
            raise FriendProtoError("player_id is required")
        if player_id in seen:
            continue
        seen.add(player_id)
        cleaned.append(player_id)
    if not cleaned:
        raise FriendProtoError("at least one player_id is required")
    return b"".join(encode_string(2, player_id) for player_id in cleaned)
