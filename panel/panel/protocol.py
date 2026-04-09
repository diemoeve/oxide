import json
import struct
from .crypto import MAX_MESSAGE_SIZE


def encode_frame(data: bytes) -> bytes:
    if len(data) > MAX_MESSAGE_SIZE:
        raise ValueError(f"message too large: {len(data)}")
    return struct.pack("<I", len(data)) + data


def decode_frame(buf: bytes) -> tuple[bytes, int]:
    if len(buf) < 4:
        raise ValueError("incomplete frame header")
    length = struct.unpack("<I", buf[:4])[0]
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"message too large: {length}")
    if len(buf) < 4 + length:
        raise ValueError("incomplete frame body")
    return buf[4 : 4 + length], 4 + length


async def read_packet(reader, crypto) -> dict:
    len_buf = await reader.readexactly(4)
    length = struct.unpack("<I", len_buf)[0]
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"message too large: {length}")
    encrypted = await reader.readexactly(length)
    plaintext = crypto.decrypt(encrypted)
    return json.loads(plaintext)


async def write_packet(writer, crypto, packet: dict):
    plaintext = json.dumps(packet).encode()
    encrypted = crypto.encrypt(plaintext)
    writer.write(struct.pack("<I", len(encrypted)))
    writer.write(encrypted)
    await writer.drain()
