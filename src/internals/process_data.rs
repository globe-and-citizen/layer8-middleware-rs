use std::collections::HashMap;

use base64::{self, engine::general_purpose::URL_SAFE as base64_enc_dec, Engine as _};

use layer8_interceptor_rs::{
    crypto::Jwk,
    types::{Request, Response},
};

fn process_data(raw_data: &str, key: Jwk) -> Result<Request, Response> {
    let enc = serde_json::from_str::<HashMap<String, serde_json::Value>>(raw_data)
        .expect("a valid json object should be deserializable to the hashmap");

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
        .decode(val.to_string())
        .map_err(|err| Response {
            status: 500,
            status_text: format!("Could not decode request {err}"),
            ..Default::default()
        })?;

    let decrypted_data = key
        .symmetric_decrypt(&decoded_data)
        .map_err(|err| Response {
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
