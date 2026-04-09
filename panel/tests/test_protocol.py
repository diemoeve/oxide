from panel.protocol import encode_frame, decode_frame

def test_frame_roundtrip():
    data = b"hello frame"
    encoded = encode_frame(data)
    assert len(encoded) == 4 + len(data)
    decoded, consumed = decode_frame(encoded)
    assert decoded == data
    assert consumed == len(encoded)


def test_frame_oversized():
    from panel.crypto import MAX_MESSAGE_SIZE
    try:
        encode_frame(b"\x00" * (MAX_MESSAGE_SIZE + 1))
        assert False, "should reject"
    except ValueError:
        pass
