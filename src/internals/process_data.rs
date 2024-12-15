use std::collections::HashMap;

use base64::{self, engine::general_purpose::URL_SAFE as base64_enc_dec, Engine as _};

use layer8_primitives::{
    crypto::Jwk,
    types::{Request, Response},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ProcessedData {
    pub request: Option<Request>,
    pub response: Option<Response>,
}

pub(crate) fn process_data(raw_data: &str, key: &Jwk) -> Result<Request, Response> {
    let enc =
        serde_json::from_str::<HashMap<String, serde_json::Value>>(raw_data).expect("a valid json object should be deserializable to the hashmap");

    let val = match enc.get("data") {
        Some(val) => val,
        None => {
            return Err(Response {
                status: 400,
                status_text: "there is no entry 'data' from the raw data provided".to_string(),
                ..Default::default()
            })
        }
    };

    let decoded_data = base64_enc_dec
        .decode(val.as_str().expect("expected the value to be a string").as_bytes())
        .map_err(|err| Response {
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
    })
}

#[derive(Deserialize)]
pub struct UrlPath {
    pub _type: TypeInformation,
}

#[derive(Deserialize)]
pub struct TypeInformation {
    pub _type: String,
    pub value: String,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use base64::{self, engine::general_purpose::URL_SAFE as base64_enc_dec, Engine as _};
    use serde_json::json;
    use wasm_bindgen_test::*;

    use layer8_primitives::{
        crypto::{generate_key_pair, Jwk, KeyUse},
        types::Request,
    };

    use super::process_data;

    #[allow(dead_code)]
    #[wasm_bindgen_test]
    fn test_process_data() {
        let (priv_key, pub_key) = generate_key_pair(KeyUse::Ecdh).unwrap();
        let shared_secret = priv_key.get_ecdh_shared_secret(&pub_key).unwrap();

        let encrypt = |data: &Request, key: Jwk| {
            let data = serde_json::to_vec(data).unwrap();
            let encrypted_data = key.symmetric_encrypt(&data).unwrap();
            json!( { "data": base64_enc_dec.encode(&encrypted_data) }).to_string()
        };

        // process data with valid key
        {
            let raw_data = encrypt(
                &Request {
                    method: "GET".to_string(),
                    headers: HashMap::from([("x-test".to_string(), "test".to_string())]),
                    body: serde_json::to_vec(&HashMap::from([("test".to_string(), "test".to_string())])).unwrap(),
                    url_path: None,
                },
                shared_secret.clone(),
            );

            let val = match process_data(&raw_data, &shared_secret) {
                Ok(val) => val,
                Err(err) => panic!("expected the process_data to return a valid request: {}", err.status_text),
            };

            assert_eq!(val.method, "GET");
            assert_eq!(
                val.body,
                serde_json::to_vec(&HashMap::from([("test".to_string(), "test".to_string())])).unwrap()
            );
        }

        let (priv_key2, pub_key2) = generate_key_pair(KeyUse::Ecdh).unwrap();
        let shared_secret2 = priv_key2.get_ecdh_shared_secret(&pub_key2).unwrap();

        // process data invalid key
        {
            let raw_data = encrypt(
                &Request {
                    method: "GET".to_string(),
                    headers: HashMap::from([("x-test".to_string(), "test".to_string())]),
                    body: serde_json::to_vec(&HashMap::from([("test".to_string(), "test".to_string())])).unwrap(),
                    url_path: None,
                },
                shared_secret2.clone(),
            );

            let val = match process_data(&raw_data, &shared_secret2) {
                Ok(val) => val,
                Err(err) => panic!("expected the process_data to return a valid request: {}", err.status_text),
            };

            assert_eq!(val.method, "GET");
            assert_eq!(
                val.body,
                serde_json::to_vec(&HashMap::from([("test".to_string(), "test".to_string())])).unwrap()
            );
        }
    }
}
