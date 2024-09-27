use layer8_interceptor_rs::{crypto::Jwk, types::Response};

use crate::js_wrapper::{JsWrapper, Value};

pub fn prepare_data(res: &Value, data: &Value, sym_key: &Jwk, jwt: String) -> Response {
    let mut js_response = Response {
        body: serde_json::to_vec(data.get_value()).expect("we implemented Serialize for JsWrapper; qed"),
        status: 200,
        ..Default::default()
    };

    if let JsWrapper::Object(mapping) = res.get_value() {
        for (k, val) in mapping {
            match k.as_str() {
                "statusCode" => {
                    let val = val.to_number().expect("this field expected a number");
                    js_response.status = val as u16
                }
                "statusText" => {
                    let val = val.to_string().expect("this field expected a string");
                    js_response.status_text = val.clone()
                }
                "headers" => match val {
                    JsWrapper::Object(val) => {
                        let mut headers = Vec::new();
                        for (k, val) in val {
                            headers.push((k.clone(), val.to_string().expect("this field expected a string")));
                        }

                        js_response.headers = headers
                    }

                    JsWrapper::Null | JsWrapper::Undefined => {
                        // do nothing
                    }

                    _ => unimplemented!(), // infallible; triggers for debugging
                },
                _ => {}
            }
        }
    } else {
        unimplemented!() // infallible; triggers for debugging
    }

    let body = sym_key
        .symmetric_encrypt(&serde_json::to_vec(&js_response).expect("the type implements Serialize"))
        .expect("no internal errors expected on encryption");

    Response {
        body,
        status: js_response.status,
        status_text: js_response.status_text,
        headers: vec![("content-type".to_string(), "application/json".to_string()), ("mp-JWT".to_string(), jwt)],
    }
}

#[cfg(test)]
mod tests {
    use layer8_interceptor_rs::{
        crypto::{generate_key_pair, KeyUse},
        types::Response,
    };
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::*;

    use crate::js_wrapper::Value;

    use super::prepare_data;

    #[wasm_bindgen_test]
    fn test_prepare_data() {
        let (priv_key, pub_key) = generate_key_pair(KeyUse::Ecdh).unwrap();
        let shared_secret = priv_key.get_ecdh_shared_secret(&pub_key).unwrap();

        // prepare data with object body
        {
            let data = js_sys::Object::new();
            js_sys::Reflect::set(&data, &"hello".into(), &JsValue::from_str("world")).unwrap();

            let res = js_sys::Object::new();
            js_sys::Reflect::set(&res, &"statusCode".into(), &JsValue::from_f64(200.0)).unwrap();
            js_sys::Reflect::set(&res, &"statusText".into(), &JsValue::from_str("OK")).unwrap();
            js_sys::Reflect::set(
                &res,
                &"headers".into(),
                &JsValue::from({
                    let headers = js_sys::Object::new();
                    js_sys::Reflect::set(&headers, &"x-key".into(), &JsValue::from_str("value")).unwrap();
                    headers
                }),
            )
            .unwrap();

            let res: Value = JsValue::from(res).try_into().unwrap();
            let data: Value = JsValue::from(data).try_into().unwrap();
            let got = prepare_data(&res, &data, &shared_secret, "test_mp_jwt".to_string());
            assert_eq!(got.status, 200);
            assert_eq!(got.status_text, "OK".to_string());
            let data = {
                let data = shared_secret.symmetric_decrypt(&got.body).unwrap();
                serde_json::from_slice::<Response>(&data).unwrap()
            };

            let header_present = data.headers.iter().any(|(k, v)| {
                if k == "x-key" {
                    return v.eq(&"value");
                }

                false
            });

            assert!(header_present);
            assert_eq!(data.body, br#"{"hello":"world"}"#.to_vec(),);
        }

        // prepare data with array body
        {
            let data = js_sys::Array::new();
            data.push(&JsValue::from_str("hello"));
            let len_ = data.push(&JsValue::from_str("world"));
            assert!(len_ == 2);

            let res = js_sys::Object::new();
            js_sys::Reflect::set(&res, &"statusCode".into(), &JsValue::from_f64(200.0)).unwrap();
            js_sys::Reflect::set(&res, &"statusText".into(), &JsValue::from_str("OK")).unwrap();
            js_sys::Reflect::set(
                &res,
                &"headers".into(),
                &JsValue::from({
                    let headers = js_sys::Object::new();
                    js_sys::Reflect::set(&headers, &"x-key".into(), &JsValue::from_str("value")).unwrap();
                    headers
                }),
            )
            .unwrap();

            let res: Value = JsValue::from(res).try_into().unwrap();
            let data: Value = JsValue::from(data).try_into().unwrap();
            let got = prepare_data(&res, &data, &shared_secret, "test_mp_jwt".to_string());
            assert_eq!(got.status, 200);
            assert_eq!(got.status_text, "OK".to_string());
            let data = {
                let data = shared_secret.symmetric_decrypt(&got.body).unwrap();
                serde_json::from_slice::<Response>(&data).unwrap()
            };

            assert_eq!(String::from_utf8_lossy(&data.body), r#"["hello","world"]"#);
        }

        // prepare data with string body
        {
            let data = JsValue::from_str("hello world");
            let res = js_sys::Object::new();
            js_sys::Reflect::set(&res, &"statusCode".into(), &JsValue::from_f64(200.0)).unwrap();
            js_sys::Reflect::set(&res, &"statusText".into(), &JsValue::from_str("OK")).unwrap();
            js_sys::Reflect::set(
                &res,
                &"headers".into(),
                &JsValue::from({
                    let headers = js_sys::Object::new();
                    js_sys::Reflect::set(&headers, &"x-key".into(), &JsValue::from_str("value")).unwrap();
                    headers
                }),
            )
            .unwrap();

            let res: Value = JsValue::from(res).try_into().unwrap();
            let data: Value = JsValue::from(data).try_into().unwrap();
            let got = prepare_data(&res, &data, &shared_secret, "test_mp_jwt".to_string());
            assert_eq!(got.status, 200);
            assert_eq!(got.status_text, "OK".to_string());
            let data = {
                let data = shared_secret.symmetric_decrypt(&got.body).unwrap();
                serde_json::from_slice::<Response>(&data).unwrap()
            };

            assert_eq!(String::from_utf8_lossy(&data.body), r#""hello world""#);
        }

        // with nil headers
        {
            let data = JsValue::from_str("hello world");
            let res = js_sys::Object::new();
            js_sys::Reflect::set(&res, &"statusCode".into(), &JsValue::from_f64(200.0)).unwrap();
            js_sys::Reflect::set(&res, &"statusText".into(), &JsValue::from_str("OK")).unwrap();
            js_sys::Reflect::set(&res, &"headers".into(), &JsValue::NULL).unwrap();

            let res: Value = JsValue::from(res).try_into().unwrap();
            let data: Value = JsValue::from(data).try_into().unwrap();
            let got = prepare_data(&res, &data, &shared_secret, "test_mp_jwt".to_string());
            assert_eq!(got.status, 200);
            assert_eq!(got.status_text, "OK".to_string());
            let data = {
                let data = shared_secret.symmetric_decrypt(&got.body).unwrap();
                serde_json::from_slice::<Response>(&data).unwrap()
            };

            assert_eq!(String::from_utf8_lossy(&data.body), r#""hello world""#);
        }
    }
}
