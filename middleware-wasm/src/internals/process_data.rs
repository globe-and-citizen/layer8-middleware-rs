use base64::{self, engine::general_purpose::URL_SAFE as base64_enc_dec, Engine as _};

use layer8_primitives::{
    crypto::Jwk,
    types::{Request, RequestMetadata, Response},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ProcessedData {
    pub request: Option<Request>,
    pub response: Option<Response>,
}

pub fn process_data(data: &str, request_metadata: &str, key: &Jwk) -> Result<(Request, RequestMetadata), Response> {
    let decrypted_data = {
        let decoded_data = base64_enc_dec.decode(data).map_err(|err| Response {
            status: 500,
            status_text: format!("Could not decode request {err}"),
            ..Default::default()
        })?;

        let decrypted_data = key.symmetric_decrypt(&decoded_data).map_err(|err| Response {
            status: 500,
            status_text: format!("Could not decrypt request {err}"),
            ..Default::default()
        })?;

        serde_json::from_slice::<Request>(&decrypted_data).map_err(|err| Response {
            status: 500,
            status_text: format!("Could not decode request {err}"),
            ..Default::default()
        })?
    };

    let decrypted_request_metadata = {
        let decoded_request_metadata = base64_enc_dec.decode(request_metadata).map_err(|err| Response {
            status: 500,
            status_text: format!("Could not decode request metadata {err}"),
            ..Default::default()
        })?;

        let decrypted_request_metadata = key.symmetric_decrypt(&decoded_request_metadata).map_err(|err| Response {
            status: 500,
            status_text: format!("Could not decrypt request metadata {err}"),
            ..Default::default()
        })?;

        serde_json::from_slice::<RequestMetadata>(&decrypted_request_metadata).map_err(|err| Response {
            status: 500,
            status_text: format!("Could not decode request metadata {err}"),
            ..Default::default()
        })?
    };

    Ok((decrypted_data, decrypted_request_metadata))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use layer8_primitives::{
        crypto::{generate_key_pair, Jwk, KeyUse},
        types::{Request, RequestMetadata, RoundtripEnvelope},
    };

    use super::process_data;

    #[test]
    fn test_process_data() {
        let (priv_key, pub_key) = generate_key_pair(KeyUse::Ecdh).unwrap();
        let shared_secret = priv_key.get_ecdh_shared_secret(&pub_key).unwrap();

        let encrypt = |data: &Request, metadata: &RequestMetadata, key: Jwk| {
            let data = {
                let data = serde_json::to_vec(data).unwrap();
                let encrypted_data = key.symmetric_encrypt(&data).unwrap();

                serde_json::to_string(&layer8_primitives::types::Layer8Envelope::Http(RoundtripEnvelope::encode(
                    &encrypted_data,
                )))
                .unwrap()
            };

            let metadata = {
                let metadata = serde_json::to_vec(metadata).unwrap();
                let encrypted_metadata = key.symmetric_encrypt(&metadata).unwrap();

                serde_json::to_string(&layer8_primitives::types::Layer8Envelope::Http(RoundtripEnvelope::encode(
                    &encrypted_metadata,
                )))
                .unwrap()
            };

            (data, metadata)
        };

        // process data with valid key
        {
            let (raw_data, raw_metdata) = encrypt(
                &Request {
                    body: serde_json::to_vec(&HashMap::from([("test".to_string(), "test".to_string())])).unwrap(),
                },
                &RequestMetadata {
                    method: "GET".to_string(),
                    headers: HashMap::from([("x-test".to_string(), "test".to_string())]),
                    url_path: None,
                },
                shared_secret.clone(),
            );

            let (req, req_metadata) = match process_data(&raw_data, &raw_metdata, &shared_secret) {
                Ok(val) => val,
                Err(err) => panic!("expected the process_data to return a valid request: {}", err.status_text),
            };

            assert_eq!(req_metadata.method, "GET");
            assert_eq!(
                req.body,
                serde_json::to_vec(&HashMap::from([("test".to_string(), "test".to_string())])).unwrap()
            );
        }

        let (priv_key2, pub_key2) = generate_key_pair(KeyUse::Ecdh).unwrap();
        let shared_secret2 = priv_key2.get_ecdh_shared_secret(&pub_key2).unwrap();

        // process data invalid key
        {
            let (raw_data, raw_metadata) = encrypt(
                &Request {
                    body: serde_json::to_vec(&HashMap::from([("test".to_string(), "test".to_string())])).unwrap(),
                },
                &RequestMetadata {
                    method: "GET".to_string(),
                    headers: HashMap::from([("x-test".to_string(), "test".to_string())]),
                    url_path: None,
                },
                shared_secret2.clone(),
            );

            let (req, req_metadata) = match process_data(&raw_data, &raw_metadata, &shared_secret2) {
                Ok(val) => val,
                Err(err) => panic!("expected the process_data to return a valid request: {}", err.status_text),
            };

            assert_eq!(req_metadata.method, "GET");
            assert_eq!(
                req.body,
                serde_json::to_vec(&HashMap::from([("test".to_string(), "test".to_string())])).unwrap()
            );
        }
    }
}
