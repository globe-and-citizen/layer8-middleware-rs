use std::collections::HashMap;

use js_sys::Object;
use wasm_bindgen::prelude::*;

use crate::{
    internals,
    js_wrapper::{self, JsWrapper, Value},
    storage::INMEM_STORAGE_INSTANCE,
};

const VERSION: &str = "1.0.26";

/// This block imports Javascript functions that are provided by the JS Runtime.
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = error)]
    fn console_error(s: &str);
}

#[allow(non_snake_case)]
#[wasm_bindgen(js_name = TestWASM)]
pub fn test_wasm() -> JsValue {
    JsValue::from_str("42")
}

#[allow(non_snake_case)]
#[wasm_bindgen(js_name = WASMMiddleware)]
pub fn wasm_middleware(req: JsValue, resp: JsValue, next: JsValue) -> JsValue {
    let req_object: Value = req.clone().try_into().unwrap();
    let headers = req_object
        .get("headers")
        .expect("this should be the request object; qed");

    let mut short_circuit = false;
    if headers.is_none() {
        short_circuit = true;
    }

    let headers_map = {
        let headers_object = headers.unwrap();
        if let JsWrapper::Object(headers) = headers_object {
            headers
        } else {
            short_circuit = true;
            &HashMap::new()
        }
    };

    if short_circuit
        || headers_map.get("x-tunnel") == None
        || headers_map.get("x-tunnel") == Some(&JsWrapper::Undefined)
        || headers_map.get("x-tunnel") == Some(&JsWrapper::Null)
    {
        // invoking next middleware
        js_sys::Function::from(next)
            .call0(&JsValue::NULL)
            .expect("expected next to be a function");
        return JsValue::NULL;
    }

    let init_ecdh = || {
        let res = INMEM_STORAGE_INSTANCE.with(|storage| {
            let mut inmem_storage = storage.take();
            let res = internals::init_ecdh::initialize_ecdh(
                Value {
                    r#type: js_wrapper::Type::Object,
                    constructor: "Object".to_string(),
                    value: headers.unwrap().clone(),
                },
                &mut inmem_storage,
            );

            storage.replace(inmem_storage);
            res
        });

        match res {
            Ok(res) => {
                js_sys::Reflect::set(&resp, &"statusCode".into(), &JsValue::from_f64(200.0))
                    .unwrap();
                js_sys::Reflect::set(
                    &resp,
                    &"statusMessage".into(),
                    &JsValue::from_str("ECDH Successfully Completed!"),
                )
                .unwrap();

                let set_header =
                    js_sys::Reflect::get(&resp, &JsValue::from_str("setHeader")).unwrap();
                let set_header = js_sys::Function::from(set_header);
                set_header
                    .call2(
                        &JsValue::NULL,
                        &JsValue::from_str("x-shared-secret"),
                        &JsValue::from_str(&res.shared_secret),
                    )
                    .expect("expected setHeader to be a function");
                set_header
                    .call2(
                        &JsValue::NULL,
                        &JsValue::from_str("mp-JWT"),
                        &JsValue::from_str(&res.mp_jwt),
                    )
                    .expect("expected setHeader to be a function");

                let end = js_sys::Reflect::get(&resp, &JsValue::from_str("end")).unwrap();
                let end = js_sys::Function::from(end);
                end.call1(&JsValue::NULL, &JsValue::from_str(&res.shared_secret))
                    .expect("expected end to be a function");
            }
            Err(err) => {
                console_error(&err);

                js_sys::Reflect::set(&resp, &"statusCode".into(), &JsValue::from_f64(500.0))
                    .unwrap();
                js_sys::Reflect::set(
                    &resp,
                    &"statusMessage".into(),
                    &JsValue::from_str("Failure to initialize ECDH"),
                )
                .unwrap();

                let end = js_sys::Reflect::get(&resp, &JsValue::from_str("end")).unwrap();
                let end = js_sys::Function::from(end);
                end.call1(
                    &JsValue::NULL,
                    &JsValue::from_str("500 Internal Server Error"),
                )
                .expect("expected end to be a function");
            }
        }
    };

    let is_ecdh_init = headers_map.get("x-ecdh-init");
    let client_uuid = headers_map.get("x-client-uuid");
    if is_ecdh_init.is_none()
        || client_uuid.is_none()
        || (is_ecdh_init.is_some() && *is_ecdh_init.unwrap() == JsWrapper::Null)
        || (is_ecdh_init.is_some() && *is_ecdh_init.unwrap() == JsWrapper::Undefined)
    {
        init_ecdh();
        return JsValue::NULL;
    }

    let is_client_init = is_ecdh_init.unwrap().to_string().unwrap();
    let client_uuid = client_uuid.unwrap().to_string().unwrap();

    // get symmetric key for this client
    let mp_jwt = INMEM_STORAGE_INSTANCE.with(|v| {
        let val = v.take();
        v.set(val.clone());
        val.jwts.get(&client_uuid).cloned()
    });

    if mp_jwt.is_none() {
        init_ecdh();
        return JsValue::NULL;
    }

    let on = {
        let on = js_sys::Reflect::get(&req, &JsValue::from_str("on")).unwrap();
        js_sys::Function::from(on)
    };

    let val = on.call1(
        &JsValue::from_str("data"),
        &JsValue::from_str(
            "function(args) {
                body += args[0].toString();
                return null;
            }",
        ),
    );

    if let Err(err) = val {
        console_error(format!("error: {:?}", err).as_str());
    }

    // let end = js_sys::Reflect::get(&resp, &JsValue::from_str("end")).unwrap();
    // let end = js_sys::Function::from(end);
    // end.call1(&JsValue::NULL, &JsValue::from_str(&res.shared_secret))
    //     .expect("expected end to be a function");

    // some work to add here

    JsValue::NULL
}

#[cfg(test)]
mod tests {
    use js_sys::Object;
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_wasm() {
        assert_eq!(super::test_wasm(), "42");
    }

    #[wasm_bindgen_test]
    fn test_mutate_value() {
        let obj = Object::new();
        // try and mutate the object
        {
            let val = JsValue::from(&obj);
            js_sys::Reflect::set(&val, &"statusCode".into(), &JsValue::from_f64(200.0)).unwrap();
        }

        // making sure the object has the property
        assert!(obj.has_own_property(&JsValue::from_str("statusCode")));
    }
}
