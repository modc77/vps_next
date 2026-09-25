from __future__ import annotations

import base64
import hashlib
import json
import secrets
import struct
from dataclasses import dataclass
from typing import Any


PROTOCOL_VERSION = 4
CHACHA20_COUNTER = 0

# Cookie Run Classic 26.8.02 / protocol v4 static material.
# Ghidra: FUN_00F1B108 -> FUN_00F3DA48 -> FUN_016AF2D4
KEY_GH = "0x007D2310"
BASE_NONCE_GH = "0x007D2330"
KEY = bytes.fromhex(
    "909d2ab54ab9769ca6bb0b4cba7da98d"
    "3f2c42d3944b881ff8587a62b000e97e"
)
BASE_NONCE = bytes.fromhex("a7935a5977760ed63530acd6")


@dataclass(frozen=True, slots=True)
class EncodedV4:
    plaintext_length: int
    padding_spaces: int
    padded_length: int
    compressed_length: int
    pre_cipher_length: int
    nonce: bytes
    ciphertext_length: int
    data_b64: str
    form_body: bytes

    @property
    def body_sha256(self) -> str:
        return hashlib.sha256(self.form_body).hexdigest()

    def public_dict(self) -> dict[str, Any]:
        return {
            "protocol_version": PROTOCOL_VERSION,
            "cipher": "ChaCha20",
            "counter": CHACHA20_COUNTER,
            "compression": "FastLZ-level1-compatible",
            "compression_policy": "LITERAL_ONLY_VALID_STREAM",
            "plaintext_length": self.plaintext_length,
            "padding_spaces": self.padding_spaces,
            "padded_length": self.padded_length,
            "compressed_length": self.compressed_length,
            "pre_cipher_length": self.pre_cipher_length,
            "nonce_hex": self.nonce.hex(),
            "ciphertext_length": self.ciphertext_length,
            "data_b64_length": len(self.data_b64),
            "form_body_length": len(self.form_body),
            "reported_length_with_nul": len(self.form_body) + 1,
            "body_sha256": self.body_sha256,
            "outer_shape": "isEncryptedData=4&data=<url-safe-base64-padded>",
            "key_gh": KEY_GH,
            "base_nonce_gh": BASE_NONCE_GH,
        }


def _rotl32(value: int, count: int) -> int:
    value &= 0xFFFFFFFF
    return ((value << count) & 0xFFFFFFFF) | (value >> (32 - count))


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 16)

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 12)

    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 8)

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 7)


def chacha20_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be 12 bytes")

    constants = struct.unpack("<4I", b"expand 32-byte k")
    key_words = struct.unpack("<8I", key)
    nonce_words = struct.unpack("<3I", nonce)
    initial = list(constants + key_words + (counter & 0xFFFFFFFF,) + nonce_words)
    work = initial.copy()

    for _ in range(10):
        # Column round.
        _quarter_round(work, 0, 4, 8, 12)
        _quarter_round(work, 1, 5, 9, 13)
        _quarter_round(work, 2, 6, 10, 14)
        _quarter_round(work, 3, 7, 11, 15)
        # Diagonal round.
        _quarter_round(work, 0, 5, 10, 15)
        _quarter_round(work, 1, 6, 11, 12)
        _quarter_round(work, 2, 7, 8, 13)
        _quarter_round(work, 3, 4, 9, 14)

    result = [
        (work[i] + initial[i]) & 0xFFFFFFFF
        for i in range(16)
    ]
    return struct.pack("<16I", *result)


def chacha20_xor(
    data: bytes,
    *,
    key: bytes,
    nonce: bytes,
    counter: int = CHACHA20_COUNTER,
) -> bytes:
    out = bytearray()
    for block_index in range((len(data) + 63) // 64):
        stream = chacha20_block(
            key,
            nonce,
            (counter + block_index) & 0xFFFFFFFF,
        )
        chunk = data[block_index * 64:(block_index + 1) * 64]
        out.extend(a ^ b for a, b in zip(chunk, stream))
    return bytes(out)


def derive_v4_nonce(pre_cipher_length: int) -> bytes:
    # FUN_00F3DA48 adds the low byte of the pre-cipher frame length to
    # every byte of the 12-byte base nonce.
    delta = pre_cipher_length & 0xFF
    return bytes((value + delta) & 0xFF for value in BASE_NONCE)


def fastlz_level1_literal_compress(data: bytes) -> bytes:
    """Emit a valid FastLZ level-1 stream using literal runs only.

    The game normally uses FUN_016A9D18 for payloads below 64 KiB. Matching
    its exact match-selection is unnecessary for protocol compatibility: the
    server's FastLZ decoder accepts any valid level-1 stream. Literal runs are
    deterministic, small, and avoid an external FastLZ dependency.
    """
    out = bytearray()
    for offset in range(0, len(data), 32):
        chunk = data[offset:offset + 32]
        if not chunk:
            continue
        out.append(len(chunk) - 1)  # ctrl < 32 => literal length ctrl + 1
        out.extend(chunk)
    return bytes(out)


def _fastlz_copy_from_output(out: bytearray, ref: int, length: int) -> None:
    if ref < 0:
        raise ValueError("invalid FastLZ back-reference")
    for _ in range(length):
        if ref < 0 or ref >= len(out):
            raise ValueError("invalid FastLZ back-reference")
        out.append(out[ref])
        ref += 1


def _fastlz_decompress_level1(data: bytes, expected_length: int | None = None) -> bytes:
    if not data:
        return b""

    ip = 0
    out = bytearray()
    ctrl = data[ip] & 0x1F
    ip += 1

    while True:
        if ctrl >= 32:
            length_code = (ctrl >> 5) - 1
            offset_high = (ctrl & 0x1F) << 8

            if length_code == 6:
                if ip >= len(data):
                    raise ValueError("truncated FastLZ length")
                length_code += data[ip]
                ip += 1

            if ip >= len(data):
                raise ValueError("truncated FastLZ offset")
            offset_low = data[ip]
            ip += 1

            ref = len(out) - offset_high - offset_low - 1
            _fastlz_copy_from_output(out, ref, length_code + 3)
        else:
            length = ctrl + 1
            end = ip + length
            if end > len(data):
                raise ValueError("truncated FastLZ literal")
            out.extend(data[ip:end])
            ip = end

        # Match the game's FUN_016AA25C stop condition: when fewer than two
        # input bytes remain, the stream is complete. The old Python decoder
        # read a final one-byte tail as another control byte, which could turn
        # a valid server response into "truncated FastLZ literal".
        if ip > len(data) - 2:
            break
        ctrl = data[ip]
        ip += 1

    result = bytes(out)
    if expected_length is not None and len(result) != expected_length:
        raise ValueError(
            f"FastLZ length mismatch: got {len(result)}, expected {expected_length}"
        )
    return result


def _fastlz_decompress_level2(data: bytes, expected_length: int | None = None) -> bytes:
    if not data:
        return b""

    ip = 0
    out = bytearray()
    ctrl = data[ip] & 0x1F
    ip += 1

    while True:
        if ctrl >= 32:
            length_code = (ctrl >> 5) - 1
            offset_high = (ctrl & 0x1F) << 8

            if length_code == 6:
                while True:
                    if ip >= len(data):
                        raise ValueError("truncated FastLZ level2 length")
                    code = data[ip]
                    ip += 1
                    length_code += code
                    if code != 0xFF:
                        break

            if ip >= len(data):
                raise ValueError("truncated FastLZ level2 offset")
            offset_low = data[ip]
            ip += 1

            ref = len(out) - offset_high - offset_low - 1
            if offset_low == 0xFF and (ctrl & 0x1F) == 0x1F:
                # Ghidra FUN_016AA920: extended level-2 distance path.
                if ip + 1 >= len(data):
                    raise ValueError("truncated FastLZ level2 far offset")
                far = (data[ip] << 8) | data[ip + 1]
                ip += 2
                ref = len(out) - 0x2000 - far

            _fastlz_copy_from_output(out, ref, length_code + 3)
        else:
            length = ctrl + 1
            end = ip + length
            if end > len(data):
                raise ValueError("truncated FastLZ level2 literal")
            out.extend(data[ip:end])
            ip = end

        # Match FUN_016AA920: stop when there is no complete next token.
        if ip >= len(data):
            break
        ctrl = data[ip]
        ip += 1

    result = bytes(out)
    if expected_length is not None and len(result) != expected_length:
        raise ValueError(
            f"FastLZ length mismatch: got {len(result)}, expected {expected_length}"
        )
    return result


def fastlz_level1_decompress(data: bytes, expected_length: int | None = None) -> bytes:
    """Decompress the FastLZ stream used by DS v4 responses.

    Cookie Run 26.8.02 dispatches through FUN_016AAB8C:
      - first byte < 0x20          => FUN_016AA25C / level 1
      - first byte & 0xE0 == 0x20  => FUN_016AA920 / level 2

    Request payloads emitted by this tool are literal-only level 1, but larger
    server responses such as initMember3 may be FastLZ level 2. Keep the public
    function name for compatibility with existing V1/V2 callers.
    """
    if not data:
        return b""
    first = data[0]
    if first < 0x20:
        return _fastlz_decompress_level1(data, expected_length=expected_length)
    if (first & 0xE0) == 0x20:
        return _fastlz_decompress_level2(data, expected_length=expected_length)
    raise ValueError(f"unsupported FastLZ level marker 0x{first:02x}")

def compact_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def encode_v4(
    plaintext: bytes,
    *,
    padding_spaces: int | None = None,
) -> EncodedV4:
    if padding_spaces is None:
        padding_spaces = secrets.randbelow(16)
    if not 0 <= padding_spaces <= 15:
        raise ValueError("padding_spaces must be 0..15")

    padded = plaintext + (b" " * padding_spaces)
    compressed = fastlz_level1_literal_compress(padded)
    frame = str(len(padded)).encode("ascii") + b"@" + compressed
    nonce = derive_v4_nonce(len(frame))
    ciphertext = chacha20_xor(
        frame,
        key=KEY,
        nonce=nonce,
        counter=CHACHA20_COUNTER,
    )
    data_b64 = base64.urlsafe_b64encode(ciphertext).decode("ascii")
    form_body = f"isEncryptedData=4&data={data_b64}".encode("ascii")

    return EncodedV4(
        plaintext_length=len(plaintext),
        padding_spaces=padding_spaces,
        padded_length=len(padded),
        compressed_length=len(compressed),
        pre_cipher_length=len(frame),
        nonce=nonce,
        ciphertext_length=len(ciphertext),
        data_b64=data_b64,
        form_body=form_body,
    )


def decode_v4_form_body(form_body: bytes | str) -> bytes:
    if isinstance(form_body, bytes):
        text = form_body.decode("ascii")
    else:
        text = form_body

    prefix = "isEncryptedData=4&data="
    if not text.startswith(prefix):
        raise ValueError("not a protocol-v4 DS form body")

    encoded = text[len(prefix):].strip()

    # Server responseData may omit URL-safe Base64 "=" padding.
    # Python's decoder requires a length divisible by 4.
    encoded += "=" * ((-len(encoded)) % 4)

    ciphertext = base64.urlsafe_b64decode(encoded)
    nonce = derive_v4_nonce(len(ciphertext))
    frame = chacha20_xor(
        ciphertext,
        key=KEY,
        nonce=nonce,
        counter=CHACHA20_COUNTER,
    )

    sep = frame.find(b"@")
    if sep <= 0:
        raise ValueError("protocol-v4 frame has no length separator")
    try:
        expected_length = int(frame[:sep].decode("ascii"))
    except ValueError as exc:
        raise ValueError("invalid protocol-v4 original length") from exc

    return fastlz_level1_decompress(
        frame[sep + 1:],
        expected_length=expected_length,
    )


def decode_v4_data_b64(data_b64: str) -> bytes:
    """
    Decode a protocol-v4 responseData value.

    Server HTTP responses wrap the encrypted payload in JSON:
      {"responseCode":200,"responseMessage":"COMPLETE","responseData":"..."}

    responseData itself is the URL-safe Base64 ciphertext, so reuse the exact
    same v4 decoder by reconstructing the outer form prefix.
    """
    value = str(data_b64 or "").strip()
    if not value:
        return b""
    return decode_v4_form_body(f"isEncryptedData=4&data={value}")
