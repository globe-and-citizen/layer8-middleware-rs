//! Code in this file is heavily AI-generated, it is placeholder code for a library that we should import instead. FIXME.

use rand::Rng;

pub fn parse_payload_from_raw_frame_bytes(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 2 {
        return Err("Data too short".to_string());
    }

    let fin = (data[0] & 0x80) != 0;
    let opcode = data[0] & 0x0F;
    let mask = (data[1] & 0x80) != 0;
    let mut payload_length = (data[1] & 0x7F) as usize;

    let mut offset = 2;

    // Handle extended payload length
    if payload_length == 126 {
        if data.len() < 4 {
            return Err("Data too short for 16-bit length".to_string());
        }
        payload_length = ((data[2] as usize) << 8) | (data[3] as usize);
        offset += 2;
    } else if payload_length == 127 {
        if data.len() < 10 {
            return Err("Data too short for 64-bit length".to_string());
        }
        payload_length = ((data[2] as usize) << 56)
            | ((data[3] as usize) << 48)
            | ((data[4] as usize) << 40)
            | ((data[5] as usize) << 32)
            | ((data[6] as usize) << 24)
            | ((data[7] as usize) << 16)
            | ((data[8] as usize) << 8)
            | (data[9] as usize);
        offset += 8;
    }

    // Get masking key if present
    let masking_key = if mask {
        if data.len() < offset + 4 {
            return Err("Data too short for masking key".to_string());
        }
        let key = [data[offset], data[offset + 1], data[offset + 2], data[offset + 3]];
        offset += 4;
        Some(key)
    } else {
        None
    };

    // Get payload
    let mut payload = Vec::new();
    if data.len() >= offset + payload_length {
        payload.extend_from_slice(&data[offset..offset + payload_length]);

        // Unmask the payload if necessary
        if let Some(key) = masking_key {
            for i in 0..payload.len() {
                payload[i] ^= key[i % 4];
            }
        }
    } else {
        return Err("Data too short for payload".to_string());
    }

    _ = fin;
    _ = opcode;
    Ok(payload)
}

pub fn construct_raw_websocket_frame(payload: &[u8], mask: bool) -> Result<Vec<u8>, String> {
    let mut frame = Vec::with_capacity(14 + payload.len());

    // First byte: FIN (1) + RSV1-3 (000) + Opcode (0001 for text)
    frame.push(0b1000_0001);

    let payload_len = payload.len();
    let mask_bit = if mask { 0b1000_0000 } else { 0 };

    match payload_len {
        0..=125 => {
            frame.push(mask_bit | payload_len as u8);
        }
        126..=65535 => {
            frame.push(mask_bit | 126);
            frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
        }
        _ => {
            frame.push(mask_bit | 127);
            frame.extend_from_slice(&(payload_len as u64).to_be_bytes());
        }
    }

    if mask {
        let mut masking_key = [0u8; 4];
        rand::rng().fill(&mut masking_key);
        frame.extend_from_slice(&masking_key);

        let masked_payload: Vec<u8> = payload.iter().enumerate().map(|(i, &byte)| byte ^ masking_key[i % 4]).collect();
        frame.extend_from_slice(&masked_payload);
    } else {
        frame.extend_from_slice(payload);
    }

    Ok(frame)
}

#[cfg(test)]
mod tests {
    use layer8_tungstenite::protocol::frame::{coding::OpCode, Frame};

    use super::*;

    #[test]
    fn test_small_payload() {
        let payload = b"Hello";
        let frame = construct_raw_websocket_frame(payload, true).unwrap();

        assert_eq!(frame[0], 0b1000_0001); // FIN + Text opcode
        assert_eq!(frame[1] & 0x7F, 5); // Payload length
        assert_eq!(frame.len(), 11); // 2 bytes header + 4 bytes mask + 5 bytes payload

        let parsed_payload = parse_payload_from_raw_frame_bytes(&frame).unwrap();
        assert_eq!(parsed_payload, payload);
    }

    #[test]
    fn test_medium_payload() {
        let payload = vec![0; 500];
        let frame = construct_raw_websocket_frame(&payload, true).unwrap();

        assert_eq!(frame[0], 0b1000_0001); // FIN + Text opcode
        assert_eq!(frame[1] & 0x7F, 126); // Extended payload marker
        assert_eq!(u16::from_be_bytes([frame[2], frame[3]]), 500); // Extended length
        assert_eq!(frame.len(), 508); // 2 bytes header + 2 bytes extended length + 4 bytes mask + 500 bytes payload

        let parsed_payload = parse_payload_from_raw_frame_bytes(&frame).unwrap();
        assert_eq!(parsed_payload, payload);
    }

    #[test]
    fn test_large_payload() {
        let payload = vec![0; 70000];
        let frame = construct_raw_websocket_frame(&payload, true).unwrap();

        assert_eq!(frame[0], 0b1000_0001); // FIN + Text opcode
        assert_eq!(frame[1] & 0x7F, 127); // Extended payload marker
        let len = u64::from_be_bytes([frame[2], frame[3], frame[4], frame[5], frame[6], frame[7], frame[8], frame[9]]);
        assert_eq!(len, 70000); // Extended length
        assert_eq!(frame.len(), 70014); // 2 bytes header + 8 bytes extended length + 4 bytes mask + 70000 bytes payload

        let parsed_payload = parse_payload_from_raw_frame_bytes(&frame).unwrap();
        assert_eq!(parsed_payload, payload);
    }

    #[test]
    fn test_masked_payload_verification() {
        let payload = b"Test message";
        let frame = construct_raw_websocket_frame(payload, true).unwrap();

        // Extract masking key
        let mask_start = if frame[1] & 0x7F <= 125 {
            2
        } else if frame[1] & 0x7F == 126 {
            4
        } else {
            10
        };
        let masking_key = &frame[mask_start..mask_start + 4];

        // Verify payload is properly masked
        let payload_start = mask_start + 4;
        for (i, &byte) in frame[payload_start..].iter().enumerate() {
            assert_eq!(byte ^ masking_key[i & 3], payload[i]);
        }

        let parsed_payload = parse_payload_from_raw_frame_bytes(&frame).unwrap();
        assert_eq!(parsed_payload, payload);
    }

    #[test]
    fn test_consistency_with_tungstenite() {
        for i in [b"Hello, World!", vec![0; 70000].as_slice()] {
            let frame = Frame::message(i.to_vec(), OpCode::Data(layer8_tungstenite::protocol::frame::coding::Data::Text), false);

            let mut output = Vec::new();
            if let Err(err) = frame.format(&mut output) {
                panic!("Failed to format frame: {:?}", err);
            }

            let parsed_payload = parse_payload_from_raw_frame_bytes(&output).unwrap();
            assert_eq!(parsed_payload, i);
        }
    }
}
