use std::collections::HashMap;

use jsonwebtoken::{EncodingKey, Header};
use layer8_interceptor_rs::crypto::base64_to_jwk;
use serde::Serialize;

use crate::{
    js_wrapper::{JsWrapper, Type, Value},
    storage::InMemStorage,
};

#[derive(Debug)]
pub struct InitEcdhReturn {
    pub shared_secret: String,
    pub server_public_key: String,
    pub mp_jwt: String,
}

/// Initializes the ECDH key exchange
///
/// Arguments:
///   - request: the request object
///
/// Returns:
///   - sharedSecret: the shared secret
///   - pub: the server public key
///   - mpJWT: the JWT
///   - error: an error if the function fails
pub fn initialize_ecdh(
    headers: Value,
    inmem_storage: &mut InMemStorage,
) -> Result<InitEcdhReturn, String> {
    let required = HashMap::from([
        ("x-ecdh-init".to_string(), Type::String),
        ("x-client-uuid".to_string(), Type::String),
        ("mp-jwt".to_string(), Type::String),
    ]);

    let mut missing = Vec::new();
    let mut invalid = Vec::new();
    for (key, v) in required.iter() {
        let val = headers.get(key)?;
        if val.is_none() {
            missing.push(key.as_str());
            continue;
        }

        let val = val.unwrap();
        if val.get_type().ne(v) {
            invalid.push(key.as_str());
        }
    }

    if !missing.is_empty() {
        return Err(format!(
            "Missing required headers: {:?}",
            missing.join(", ")
        ));
    }

    if !invalid.is_empty() {
        return Err(format!("Invalid headers: {:?}", invalid.join(", ")));
    }

    let user_pub_jwk = {
        let user_pub_jwk = match headers
            .get("x-ecdh-init")
            .expect("we know the header is a map; qed")
            .expect("we know the value exists; qed")
        {
            JsWrapper::String(s) => s,
            _ => unreachable!("we know the value is a string; qed"),
        };

        base64_to_jwk(user_pub_jwk).map_err(|e| format!("failure to decode userPubJwk: {e}"))?
    };

    let shared_secret = inmem_storage
        .ecdh
        .get_private_key()
        .get_ecdh_shared_secret(&user_pub_jwk)
        .map_err(|e| format!("unable to get ECDH shared secret: {e}"))?;

    let client_uuid = {
        let val = headers
            .get("x-client-uuid")
            .expect("we know the header is a map; qed")
            .expect("we know the value exists; qed");
        match val {
            JsWrapper::String(s) => s.as_str(),
            _ => unreachable!("we know the value is a string; qed"),
        }
    };

    // adding the shared secret to the keys
    inmem_storage.keys.add(client_uuid, shared_secret.clone());
    let b64_shared_secret = shared_secret.export_as_base64();
    let b64_pub_key = inmem_storage.ecdh.get_public_key().export_as_base64();

    let mp_jwt = {
        let val = headers
            .get("mp-jwt")
            .expect("we know the header is a map; qed")
            .expect("we know the value exists; qed");
        match val {
            JsWrapper::String(s) => s.as_str(),
            _ => unreachable!("we know the value is a string; qed"),
        }
    };

    Ok(InitEcdhReturn {
        shared_secret: b64_shared_secret,
        server_public_key: b64_pub_key,
        mp_jwt: mp_jwt.to_string(),
    })
}

// todo: have a utils module for this
#[derive(Debug, Serialize)]
struct StandardClaims {
    expires_at: u64,
}

// todo: have a utils module for this
pub fn generate_standard_token(secret_key: &str, time_now: u64) -> Result<String, String> {
    let claims = StandardClaims {
        expires_at: time_now + (60 * 60 * 24 * 7),
    };

    jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret_key.as_bytes()),
    )
    .map_err(|e| format!("could not generate standard token: {e}"))
}

#[cfg(test)]
mod tests {
    use js_sys::Object;
    use wasm_bindgen::{prelude::*, JsValue};
    use wasm_bindgen_test::*;

    use layer8_interceptor_rs::crypto::{generate_key_pair, KeyUse};

    use super::{generate_standard_token, initialize_ecdh};
    use crate::storage::{Ecdh, InMemStorage, Jwts, Keys};

    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_namespace = Date)]
        pub fn now() -> f64;
    }

    #[wasm_bindgen_test]
    fn test_initialize_ecdh() {
        let (server_pri_key, server_pub_key) = generate_key_pair(KeyUse::Ecdh).unwrap();
        let mut inmem_storage = InMemStorage {
            ecdh: Ecdh {
                private_key: server_pri_key.clone(),
                public_key: server_pub_key.clone(),
            },
            keys: Keys(vec![]),
            jwts: Jwts(vec![]),
        };

        let b64_server_pub_key = server_pub_key.export_as_base64();

        let (client_pri_key, client_pub_key) = generate_key_pair(KeyUse::Ecdh).unwrap();
        let b64_client_pub_key = client_pub_key.export_as_base64();

        let shared_secret = server_pri_key
            .get_ecdh_shared_secret(&client_pub_key)
            .unwrap();

        let b64_shared_secret = shared_secret.export_as_base64();
        let mp_jwt =
            generate_standard_token(uuid::Uuid::new_v4().to_string().as_str(), now() as u64)
                .unwrap();

        // init with valid headers
        {
            let headers = Object::new();
            js_sys::Reflect::set(
                &headers,
                &"x-ecdh-init".into(),
                &JsValue::from_str(&b64_client_pub_key),
            )
            .unwrap();
            js_sys::Reflect::set(
                &headers,
                &"x-client-uuid".into(),
                &JsValue::from_str(&uuid::Uuid::new_v4().to_string()),
            )
            .unwrap();
            js_sys::Reflect::set(&headers, &"mp-jwt".into(), &JsValue::from_str(&mp_jwt)).unwrap();

            let headers: JsValue = headers.into();
            let val = headers.try_into().unwrap();
            let val_ = initialize_ecdh(val, &mut inmem_storage).unwrap();
        }

        // init with invalid x_ecdh_init
        {
            let headers = Object::new();
            js_sys::Reflect::set(
                &headers,
                &"x-ecdh-init".into(),
                &JsValue::from_str("invalid"),
            )
            .unwrap();
            js_sys::Reflect::set(
                &headers,
                &"x-client-uuid".into(),
                &JsValue::from_str(&uuid::Uuid::new_v4().to_string()),
            )
            .unwrap();
            js_sys::Reflect::set(&headers, &"mp-jwt".into(), &JsValue::from_str(&mp_jwt)).unwrap();

            let headers: JsValue = headers.into();
            let val = headers.try_into().unwrap();
            let err = initialize_ecdh(val, &mut inmem_storage).unwrap_err();
            //  assert!(val_.unwrap());
            assert_eq!(
                err,
                "failure to decode userPubJwk: Failure to decode userPubJWK: Invalid padding"
            )
        }

        // init with no headers
        {
            let headers: JsValue = Object::new().into();
            let val = headers.try_into().unwrap();
            let err = initialize_ecdh(val, &mut inmem_storage).unwrap_err();
            //  assert!(val_.unwrap());
            assert_eq!(
                err,
                "Missing required headers: \"x-client-uuid, mp-jwt, x-ecdh-init\""
            )
        }

        // init with invalid header types
        {
            let headers = Object::new();
            js_sys::Reflect::set(&headers, &"x-ecdh-init".into(), &JsValue::from_f64(111.0))
                .unwrap();
            js_sys::Reflect::set(&headers, &"x-client-uuid".into(), &JsValue::from_f64(111.0))
                .unwrap();
            js_sys::Reflect::set(&headers, &"mp-jwt".into(), &JsValue::from_f64(111.0)).unwrap();

            let headers: JsValue = headers.into();
            let val = headers.try_into().unwrap();
            let err = initialize_ecdh(val, &mut inmem_storage).unwrap_err();
            //  assert!(val_.unwrap());
            assert_eq!(
                err,
                "Invalid headers: \"mp-jwt, x-ecdh-init, x-client-uuid\""
            )
        }
    }
}
