use crate::constants::MAX_MESSAGE_SIZE;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("message too large: {0} bytes")]
    TooLarge(usize),
    #[error("incomplete frame")]
    Incomplete,
}

pub fn encode_frame(data: &[u8]) -> Result<Vec<u8>, FrameError> {
    let len = data.len();
    if len > MAX_MESSAGE_SIZE as usize {
        return Err(FrameError::TooLarge(len));
    }
    let mut frame = Vec::with_capacity(4 + len);
    frame.extend_from_slice(&(len as u32).to_le_bytes());
    frame.extend_from_slice(data);
    Ok(frame)
}

pub fn decode_frame(buf: &[u8]) -> Result<(Vec<u8>, usize), FrameError> {
    if buf.len() < 4 {
        return Err(FrameError::Incomplete);
    }
    let len = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
    if len > MAX_MESSAGE_SIZE as usize {
        return Err(FrameError::TooLarge(len));
    }
    if buf.len() < 4 + len {
        return Err(FrameError::Incomplete);
    }
    Ok((buf[4..4 + len].to_vec(), 4 + len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let data = b"hello frame";
        let encoded = encode_frame(data).unwrap();
        assert_eq!(&encoded[..4], &(data.len() as u32).to_le_bytes());
        let (decoded, consumed) = decode_frame(&encoded).unwrap();
        assert_eq!(decoded, data);
        assert_eq!(consumed, 4 + data.len());
    }

    #[test]
    fn reject_oversized_message() {
        let data = vec![0u8; (crate::constants::MAX_MESSAGE_SIZE as usize) + 1];
        assert!(matches!(encode_frame(&data), Err(FrameError::TooLarge(_))));
    }

    #[test]
    fn incomplete_frame_header() {
        assert!(matches!(decode_frame(&[0, 0]), Err(FrameError::Incomplete)));
    }

    #[test]
    fn incomplete_frame_body() {
        let mut buf = (100u32).to_le_bytes().to_vec();
        buf.extend_from_slice(&[0u8; 50]);
        assert!(matches!(decode_frame(&buf), Err(FrameError::Incomplete)));
    }

    #[test]
    fn reject_oversized_length_prefix() {
        let buf = (crate::constants::MAX_MESSAGE_SIZE + 1)
            .to_le_bytes()
            .to_vec();
        assert!(matches!(decode_frame(&buf), Err(FrameError::TooLarge(_))));
    }
}
