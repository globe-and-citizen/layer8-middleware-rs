use std::collections::HashMap;

use layer8_interceptor_rs::crypto::base64_to_jwk;

use crate::js_wrapper::{JsWrapper, Type, Value};
use crate::storage::INMEM_STORAGE_INSTANCE;

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
fn initialize_ecdh(headers: Value) -> Result<InitEcdhReturn, String> {
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
        if val.get_type().eq(v) {
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

    let shared_secret = INMEM_STORAGE_INSTANCE
        .with(|val| {
            let val_ = val.take();
            val.replace(val_.clone());
            val_
        })
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
    INMEM_STORAGE_INSTANCE.with(|val| {
        let mut val_ = val.take();
        val_.keys.add(client_uuid, shared_secret.clone());
        val.replace(val_);
    });

    let b64_shared_secret = shared_secret.export_as_base64();
    let b64_pub_key = INMEM_STORAGE_INSTANCE.with(|val| {
        let val_ = val.take();
        let pub_key = val_.ecdh.get_public_key().export_as_base64();
        val.replace(val_);
        pub_key
    });

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
