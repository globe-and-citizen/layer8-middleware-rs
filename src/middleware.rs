use std::{cell::Cell, collections::HashMap, os::unix::process};

use base64::{self, engine::general_purpose::URL_SAFE as base64_enc_dec, Engine as _};
use js_sys::{Object, Uint8Array};
use layer8_interceptor_rs::types::Response;
use mime_sniffer::MimeTypeSniffer;
use wasm_bindgen::prelude::*;

use crate::{
    encrypted_image,
    internals::{self, prepare_data::prepare_data, process_data::process_data},
    js_wrapper::{self, JsWrapper, Value},
    storage::INMEM_STORAGE_INSTANCE,
};

const VERSION: &str = "1.0.26";

thread_local! {
    // The hook using this value might outlive the function it gets called in, ok as is
    // since the wasm runtime is single threaded.
    static BODY: Cell<String> = Cell::new("".to_string());
}

#[wasm_bindgen(module = "src/js/higher_order_fns.js")]
extern "C" {
    #[wasm_bindgen(js_name = array_fn)]
    fn array(dest: JsValue, fs: &JsValue) -> JsValue;

    #[wasm_bindgen(js_name = single_fn)]
    fn single(dest: JsValue, fs: &JsValue) -> JsValue;

    #[wasm_bindgen(js_name = serve_static_fn)]
    fn serve_static(dir: JsValue) -> JsValue;
}

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
pub fn wasm_middleware(req: JsValue, res: JsValue, next: JsValue) -> JsValue {
    let req_object: Value = req.clone().try_into().unwrap();
    let headers = req_object.get("headers").expect("this should be the request object; qed");

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

    let init_ecdh = |resp: &JsValue| {
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
                js_sys::Reflect::set(&resp, &"statusCode".into(), &JsValue::from_f64(200.0)).unwrap();
                js_sys::Reflect::set(&resp, &"statusMessage".into(), &JsValue::from_str("ECDH Successfully Completed!")).unwrap();

                let set_header = js_sys::Reflect::get(&resp, &JsValue::from_str("setHeader")).unwrap();
                let set_header = js_sys::Function::from(set_header);
                set_header
                    .call2(
                        &JsValue::NULL,
                        &JsValue::from_str("x-shared-secret"),
                        &JsValue::from_str(&res.shared_secret),
                    )
                    .expect("expected setHeader to be a function");
                set_header
                    .call2(&JsValue::NULL, &JsValue::from_str("mp-JWT"), &JsValue::from_str(&res.mp_jwt))
                    .expect("expected setHeader to be a function");

                let end = js_sys::Reflect::get(&resp, &JsValue::from_str("end")).unwrap();
                let end = js_sys::Function::from(end);
                end.call1(&JsValue::NULL, &JsValue::from_str(&res.shared_secret))
                    .expect("expected end to be a function");
            }
            Err(err) => {
                console_error(&err);

                js_sys::Reflect::set(&resp, &"statusCode".into(), &JsValue::from_f64(500.0)).unwrap();
                js_sys::Reflect::set(&resp, &"statusMessage".into(), &JsValue::from_str("Failure to initialize ECDH")).unwrap();

                let end = js_sys::Reflect::get(&resp, &JsValue::from_str("end")).unwrap();
                let end = js_sys::Function::from(end);
                end.call1(&JsValue::NULL, &JsValue::from_str("500 Internal Server Error"))
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
        init_ecdh(&res);
        return JsValue::NULL;
    }

    let is_client_init = is_ecdh_init.unwrap().to_string().unwrap();
    let client_uuid = client_uuid.unwrap().to_string().unwrap();

    // get symmetric key for this client
    let symmetric_key = {
        let symmetric_key = INMEM_STORAGE_INSTANCE.with(|val| {
            let val_ = val.take();
            val.replace(val_.clone());
            val_.keys.get(&client_uuid).cloned()
        });

        match symmetric_key {
            Some(val) => val,
            None => {
                init_ecdh(&res);
                return JsValue::NULL;
            }
        }
    };

    // get the JWT for this client
    let mp_jwt = {
        let mp_jwt = INMEM_STORAGE_INSTANCE.with(|v| {
            let val = v.take();
            v.set(val.clone());
            val.jwts.get(&client_uuid).cloned()
        });

        match mp_jwt {
            Some(val) => val,
            None => {
                init_ecdh(&res);
                return JsValue::NULL;
            }
        }
    };

    //  // here for us to reference(have options) since wasm_bindgen docs are ambiguous on higher order functions
    // let on = {
    //     let on = js_sys::Reflect::get(&req, &JsValue::from_str("on")).unwrap();
    //     js_sys::Function::from(on)
    // };
    // let val = on.call1(
    //     &JsValue::from_str("data"),
    //     &JsValue::from_str(
    //         "function(args) {
    //             body += args[0].toString();
    //             return null;
    //         }",
    //     ),
    // );
    // let end = js_sys::Reflect::get(&resp, &JsValue::from_str("end")).unwrap();
    // let end = js_sys::Function::from(end);
    // end.call1(&JsValue::NULL, &JsValue::from_str(&res.shared_secret))
    //     .expect("expected end to be a function");

    let add_event_listener = js_sys::Function::from(
        js_sys::Reflect::get(&req, &JsValue::from_str("addEventListener")).expect("expected req to have an addEventListener method"),
    );

    // data event listener
    let on_data: &Closure<dyn FnMut(wasm_bindgen::JsValue) -> JsValue> = &Closure::new(|arg| {
        let val_ = js_sys::Reflect::get(&arg, &JsValue::from_str("toString"))
            .expect("expected arg to have a toString method")
            .as_string()
            .expect("expected toString to return a string");

        BODY.with(|body_| {
            let mut body = body_.take();
            body.push_str(&val_);
            body_.set(body);
        });

        JsValue::NULL
    });

    let res_ = res.clone();
    let on_end: &Closure<dyn FnMut(wasm_bindgen::JsValue) -> JsValue> = &Closure::new(|_arg| {
        // let raw_data = BODY.with(|body_| body_.take());

        // let request = match process_data(&raw_data, &symmetric_key) {
        //     Ok(req) => req,
        //     Err(response) => {
        //         js_sys::Reflect::set(&res_, &"statusCode".into(), &JsValue::from_f64(response.status as f64))
        //             .expect("expected resp to be a mutable object");
        //         js_sys::Reflect::set(&res_, &"statusMessage".into(), &JsValue::from_str(&response.status_text))
        //             .expect("expected resp to be a mutable object");
        //         return JsValue::NULL;
        //     }
        // };

        // // todo
        // JsValue::NULL
        todo!()
    });

    let on_end = on_end.as_ref().unchecked_ref();
    let on_data = on_data.as_ref().unchecked_ref();
    {
        if let Err(err) = add_event_listener.call1(&JsValue::from_str("data"), on_data) {
            console_error(
                &err.as_string()
                    .unwrap_or(" Error: Failed to add event listener to request object.".to_string()),
            );
            return JsValue::NULL;
        }

        if let Err(err) = add_event_listener.call1(&JsValue::from_str("end"), on_end) {
            console_error(
                &err.as_string()
                    .unwrap_or(" Error: Failed to add event listener to request object.".to_string()),
            );
            return JsValue::NULL;
        }
    }

    // Overwrite all response functions
    let respond: &Closure<dyn FnMut(wasm_bindgen::JsValue) -> JsValue> = {
        let resp_ = res.clone(); // No clean way of running away from this. Should be ok since were done with mutations, check if there's a bug 💀
        &Closure::new(move |arg: JsValue| {
            let val: Value = arg.try_into().expect("expected arg to be a Value object");
            let res: Value = resp_.clone().try_into().expect("expected resp to be a Value object");
            let response = prepare_data(&res, &val, &symmetric_key, mp_jwt.clone());

            js_sys::Reflect::set(&resp_, &"statusCode".into(), &JsValue::from_f64(response.status as f64))
                .expect("expected resp to be a mutable object");
            js_sys::Reflect::set(&resp_, &"statusMessage".into(), &JsValue::from_str(&response.status_text))
                .expect("expected resp to be a mutable object");

            let set = js_sys::Reflect::get(&resp_, &JsValue::from_str("set")).unwrap();
            let set = js_sys::Function::from(set);
            for (key, val) in response.headers {
                set.call2(&JsValue::NULL, &JsValue::from_str(&key), &JsValue::from_str(&val))
                    .expect("expected set to be a function");
            }

            let end = js_sys::Reflect::get(&resp_, &JsValue::from_str("end")).unwrap();
            let end = js_sys::Function::from(end);
            end.call1(
                &JsValue::NULL,
                &JsValue::from_str(&format!("{{\"data\": \"{}\"}}", base64_enc_dec.encode(&response.body))),
            )
            .expect("expected end to be a function");

            JsValue::NULL
        })
    };

    let respond = respond.as_ref().unchecked_ref();
    js_sys::Reflect::set(&res, &JsValue::from_str("send"), respond).expect("expected resp to be a mutable object");
    js_sys::Reflect::set(&res, &JsValue::from_str("json"), respond).expect("expected resp to be a mutable object");

    JsValue::NULL
}

#[allow(non_snake_case)]
#[wasm_bindgen(js_name = ProcessMultipart)]
pub fn process_multipart(options: JsValue, fs: JsValue) -> JsValue {
    let dest = js_sys::Reflect::get(&options, &JsValue::from_str("dest"))
        .expect("expected dest to be a property")
        .as_string()
        .expect("expected dest to be a string")
        .trim_matches('/')
        .to_string();

    let single = single(JsValue::from_str(&dest), &fs);
    let array = array(JsValue::from_str(&dest), &fs);

    let return_object = Object::new();
    let value = JsValue::from(&return_object);
    js_sys::Reflect::set(&value, &"single".into(), &single).unwrap();
    js_sys::Reflect::set(&value, &"array".into(), &array).unwrap();

    value
}

#[allow(non_snake_case)]
#[wasm_bindgen(js_name = ServerStatic)]
pub fn server_static(req: JsValue, res: JsValue, dir: JsValue, fs: JsValue) -> JsValue {
    let return_encrypted_image = |res: &JsValue| {
        let array_buffer = Uint8Array::from(encrypted_image::ENCRYPTED_IMAGE_DATA);

        js_sys::Reflect::set(&res, &"statusCode".into(), &JsValue::from_f64(200.0)).expect("expected res to be a mutable object");
        js_sys::Reflect::set(&res, &"statusMessage".into(), &JsValue::from_str("OK")).expect("expected res to be a mutable object");
        js_sys::Reflect::set(&res, &"content-type".into(), &JsValue::from_str("image/png")).expect("expected res to be a mutable object");

        let end = js_sys::Reflect::get(&res, &JsValue::from_str("end")).expect("expected res to have an end method");
        let end = js_sys::Function::from(end);
        end.call1(&JsValue::NULL, &JsValue::from(array_buffer))
            .expect("expected end to be a function");

        JsValue::NULL
    };

    let mut headers: Value = js_sys::Reflect::get(&req, &JsValue::from_str("headers"))
        .expect("expected req to have a headers property")
        .try_into()
        .expect("expected headers to be a JsValue::Object; qed");

    let client_uuid = match headers.get("x-client-uuid") {
        Ok(Some(val)) => val,
        Ok(None) => return return_encrypted_image(&res),
        Err(err) => {
            console_error(&err);
            return return_encrypted_image(&res);
        }
    };

    let (mp_jwt, symmetric_key) = INMEM_STORAGE_INSTANCE.with(|val| {
        let val_ = val.take();
        val.replace(val_.clone());
        let client_uuid = client_uuid.to_string().expect("expected client_uuid to be a string; qed");

        (val_.jwts.get(&client_uuid).cloned(), val_.keys.get(&client_uuid).cloned())
    });

    let symmetric_key = match symmetric_key {
        Some(val) => val,
        None => return return_encrypted_image(&res),
    };

    let mp_jwt = match mp_jwt {
        Some(val) => val,
        None => String::from(""), // we could stick with Option but things become problematic with closures
    };

    let add_event_listener = js_sys::Function::from(
        js_sys::Reflect::get(&req, &JsValue::from_str("addEventListener")).expect("expected req to have an addEventListener method"),
    );

    // data event listener
    let on_data: &Closure<dyn FnMut(wasm_bindgen::JsValue) -> JsValue> = &Closure::new(|arg| {
        let val_ = js_sys::Reflect::get(&arg, &JsValue::from_str("toString"))
            .expect("expected arg to have a toString method")
            .as_string()
            .expect("expected toString to return a string");

        BODY.with(|body_| {
            let mut body = body_.take();
            body.push_str(&val_);
            body_.set(body);
        });

        JsValue::NULL
    });

    // end event listener
    let on_end: &Closure<dyn FnMut(wasm_bindgen::JsValue) -> JsValue> = &Closure::new(move |_arg| {
        let body = BODY.with(|body_| body_.take());

        let mut request = match process_data(&body, &symmetric_key) {
            Ok(request) => request,
            Err(response) => {
                js_sys::Reflect::set(&res, &"statusCode".into(), &JsValue::from_f64(response.status as f64))
                    .expect("expected res to be a mutable object");
                js_sys::Reflect::set(&res, &"statusMessage".into(), &JsValue::from_str(&response.status_text))
                    .expect("expected res to be a mutable object");

                return JsValue::NULL;
            }
        };

        js_sys::Reflect::set(&req, &"method".into(), &JsValue::from_str(&request.method)).expect("expected req to be a mutable object");

        for (header_key, header_val) in &request.headers {
            headers
                .set(&header_key.clone(), JsWrapper::String(header_val.clone()))
                .expect("expected headers to be a JsValue::Object; qed");
        }

        if let None = request.headers.get(&"content-type".to_string()) {
            request.headers.insert("content-type".to_string(), "application/json".to_string());
        }

        let mut body =
            serde_json::from_slice::<HashMap<String, serde_json::Value>>(&request.body).expect("expected req.body to be a valid json object");

        if let Some(url_path) = body.get("__url_path") {
            let url_path = url_path.as_str().expect("expected url_path to be a string");
            let parsed_url = url::Url::parse(url_path).expect("expected the url_path to be a valid url path, check the __url_path key");
            let query_pairs: HashMap<_, _> = parsed_url.query_pairs().into_owned().collect();

            let query = js_sys::Reflect::get(&req, &JsValue::from_str("query")).expect("expected req to have a query property");
            for (key, val) in query_pairs {
                js_sys::Reflect::set(&query, &JsValue::from_str(&key), &JsValue::from_str(&val)).expect("expected req to be a mutable object");
            }
            body.remove("__url_path").unwrap();
        }

        // getting the file path
        let path = {
            let mut path = js_sys::Reflect::get(&req, &JsValue::from_str("url"))
                .expect("expected req to have a url property")
                .as_string()
                .expect("expected url to be a string");
            if path.eq("/") {
                path = "/index.html".to_string();
            }

            path
        };

        let path = match url::form_urlencoded::parse(path.as_bytes()).next() {
            Some((key, val)) => format!("{key}={val}"), // validate!
            None => {
                js_sys::Reflect::set(&res, &"statusCode".into(), &JsValue::from_f64(500.0)).expect("expected res to be a mutable object");
                js_sys::Reflect::set(&res, &"statusMessage".into(), &JsValue::from_str("Internal Server Error"))
                    .expect("expected res to be a mutable object");

                let end = js_sys::Reflect::get(&res, &JsValue::from_str("end")).expect("expected res to have an end method");
                let end = js_sys::Function::from(end);
                end.call1(&JsValue::NULL, &JsValue::from_str("500 Internal Server Error"))
                    .expect("expected end to be a function");

                return JsValue::NULL;
            }
        };

        let path_ = dir.as_string().expect("expected the dir to be a string; qed") + &path;

        let exists_sync = js_sys::Reflect::get(&fs, &JsValue::from_str("existsSync")).expect("expected fs to have an existsSync method");
        let exists_sync = js_sys::Function::from(exists_sync);
        let exists = exists_sync
            .call1(&JsValue::NULL, &JsValue::from_str(&path_))
            .expect("expected existsSync to be a function")
            .as_bool()
            .expect("expected existsSync to return a boolean");

        if !exists {
            js_sys::Reflect::set(&res, &"statusCode".into(), &JsValue::from_f64(404.0)).expect("expected res to be a mutable object");
            js_sys::Reflect::set(&res, &"statusMessage".into(), &JsValue::from_str("Not Found")).expect("expected res to be a mutable object");

            let end = js_sys::Reflect::get(&res, &JsValue::from_str("end")).expect("expected res to have an end method");
            let end = js_sys::Function::from(end);
            end.call1(&JsValue::NULL, &JsValue::from_str(&format!("Cannot GET {path}")))
                .expect("expected end to be a function");

            return JsValue::NULL;
        }

        // return the default EncryptedImageData if the request is not a layer8 request
        if headers.is_null() || headers.is_undefined() || {
            if let Ok(val) = headers.get("x-tunnel") {
                if let Some(val) = val {
                    *val == JsWrapper::Undefined || *val == JsWrapper::Null
                } else {
                    true
                };
            }
            true
        } {
            return return_encrypted_image(&res);
        }

        // read the file
        let read_file_sync = js_sys::Reflect::get(&fs, &JsValue::from_str("readFileSync")).expect("expected fs to have a readFileSync method");
        let read_file_sync = js_sys::Function::from(read_file_sync);
        let data = js_sys::Uint8Array::new(
            &read_file_sync
                .call1(&JsValue::NULL, &JsValue::from_str(&path_))
                .expect("expected readFileSync to be a function"),
        )
        .to_vec();

        let mime_type = match data.sniff_mime_type() {
            Some(val) => val,
            None => "application/octet-stream", // TODO?
        };

        let js_res = Response {
            body: data.clone(),
            status: 200,
            status_text: "OK".to_string(),
            headers: Vec::from([("content-type".to_string(), mime_type.to_string())]),
        };

        // encrypt the file
        let encrypted = match symmetric_key
            .symmetric_encrypt(&serde_json::to_vec(&js_res).expect("expected the response to be serializable to a valid json object; qed"))
        {
            Ok(val) => val,
            Err(err) => {
                console_error(&format!("error encrypting file: {err}"));

                js_sys::Reflect::set(&res, &"statusCode".into(), &JsValue::from_f64(500.0)).expect("expected res to be a mutable object");
                js_sys::Reflect::set(&res, &"statusMessage".into(), &JsValue::from_str("Internal Server Error"))
                    .expect("expected res to be a mutable object");

                let end = js_sys::Reflect::get(&res, &JsValue::from_str("end")).expect("expected res to have an end method");
                let end = js_sys::Function::from(end);
                end.call1(&JsValue::NULL, &JsValue::from_str("500 Internal Server Error"))
                    .expect("expected end to be a function");

                return JsValue::NULL;
            }
        };

        // sending the response
        js_sys::Reflect::set(&res, &"statusCode".into(), &JsValue::from_f64(js_res.status as f64)).expect("expected res to be a mutable object");
        js_sys::Reflect::set(&res, &"statusMessage".into(), &JsValue::from_str(&js_res.status_text)).expect("expected res to be a mutable object");

        let set = js_sys::Reflect::get(&res, &JsValue::from_str("set")).unwrap();
        let set = js_sys::Function::from(set);
        set.call2(&JsValue::NULL, &JsValue::from_str("content-type"), &JsValue::from_str("application/json"))
            .expect("expected set to be a function");

        set.call2(&JsValue::NULL, &JsValue::from_str("mp-JWT"), &JsValue::from_str(&mp_jwt))
            .expect("expected set to be a function");

        let end = js_sys::Reflect::get(&res, &JsValue::from_str("end")).unwrap();
        let end = js_sys::Function::from(end);

        let data = Object::new();
        js_sys::Reflect::set(&data, &"data".into(), &JsValue::from_str(&base64_enc_dec.encode(&encrypted)))
            .expect("expected data to be a mutable object");

        end.call1(&JsValue::NULL, &JsValue::from(data)).expect("expected end to be a function");

        JsValue::NULL
    });

    let on_end = on_end.as_ref().unchecked_ref();
    let on_data = on_data.as_ref().unchecked_ref();
    {
        if let Err(err) = add_event_listener.call1(&JsValue::from_str("data"), on_data) {
            console_error(
                &err.as_string()
                    .unwrap_or(" Error: Failed to add event listener to request object.".to_string()),
            );
            return JsValue::NULL;
        }

        if let Err(err) = add_event_listener.call1(&JsValue::from_str("end"), on_end) {
            console_error(
                &err.as_string()
                    .unwrap_or(" Error: Failed to add event listener to request object.".to_string()),
            );
            return JsValue::NULL;
        }
    }

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
