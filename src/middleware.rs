use std::{cell::Cell, collections::HashMap};

use base64::{self, engine::general_purpose::URL_SAFE as base64_enc_dec, Engine as _};
use js_sys::{Function, Object, Uint8Array};
use mime_sniffer::MimeTypeSniffer;
use rand::{rngs::SmallRng, Rng, SeedableRng};
use wasm_bindgen::prelude::*;
use web_sys::{File, FormData};

use layer8_interceptor_rs::types::Response;

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
    static BODY: Cell<String> ={
        // we can use this is the part of module initialization
        log(&format!("L8 WASM Middleware version {VERSION} loaded." ));
        Cell::new("".to_string())
    }
}

#[wasm_bindgen(module = "src/higher_order_fns.js")]
extern "C" {
    fn array_fn(dest: JsValue) -> Function;
    fn single_fn(dest: JsValue) -> Function;
}

#[wasm_bindgen(module = "fs")]
extern "C" {
    #[wasm_bindgen(js_name = readFileSync, catch)]
    fn read_file(path: &str) -> Result<Buffer, JsValue>;
}

/// This block imports Javascript functions that are provided by the JS Runtime.
#[allow(non_snake_case)]
#[wasm_bindgen]
extern "C" {
    #[derive(Debug)]
    type Buffer;

    #[wasm_bindgen(js_namespace = console, js_name = error)]
    fn console_error(s: &str);

    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    // #[wasm_bindgen(js_namespace = File, js_name = "new", catch)]
    // pub fn new_file(content: Array, name: &str, options: JsValue) -> Result<JsValue, JsValue>;
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
    let headers = req_object.get("headers").expect("this should be the request object; qed").cloned();
    let mut headers_map = match headers.clone() {
        Some(JsWrapper::Object(headers)) => headers,
        _ => {
            // invoking next middleware
            js_sys::Function::from(next)
                .call0(&JsValue::NULL)
                .expect("expected next to be a function");
            return JsValue::NULL;
        }
    };

    if !headers_map.contains_key("x-tunnel")
        || headers_map.get("x-tunnel") == Some(&JsWrapper::Undefined)
        || headers_map.get("x-tunnel") == Some(&JsWrapper::Null)
    {
        // invoking next middleware
        js_sys::Function::from(next)
            .call0(&JsValue::NULL)
            .expect("expected next to be a function");
        return JsValue::NULL;
    }

    let headers = headers.unwrap();
    let init_ecdh = |resp: &JsValue| {
        let res = INMEM_STORAGE_INSTANCE.with(|storage| {
            let mut inmem_storage = storage.take();
            let res = internals::init_ecdh::initialize_ecdh(
                Value {
                    r#type: js_wrapper::Type::Object,
                    constructor: "Object".to_string(),
                    value: headers.clone(),
                },
                &mut inmem_storage,
            );

            storage.replace(inmem_storage);
            res
        });

        match res {
            Ok(res) => {
                js_sys::Reflect::set(resp, &"statusCode".into(), &JsValue::from_f64(200.0)).unwrap();
                js_sys::Reflect::set(resp, &"statusMessage".into(), &JsValue::from_str("ECDH Successfully Completed!")).unwrap();

                let set_header = js_sys::Reflect::get(resp, &JsValue::from_str("setHeader")).unwrap();
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

                let end = js_sys::Reflect::get(resp, &JsValue::from_str("end")).unwrap();
                let end = js_sys::Function::from(end);
                end.call1(&JsValue::NULL, &JsValue::from_str(&res.shared_secret))
                    .expect("expected end to be a function");
            }
            Err(err) => {
                console_error(&err);

                js_sys::Reflect::set(resp, &"statusCode".into(), &JsValue::from_f64(500.0)).unwrap();
                js_sys::Reflect::set(resp, &"statusMessage".into(), &JsValue::from_str("Failure to initialize ECDH")).unwrap();

                let end = js_sys::Reflect::get(resp, &JsValue::from_str("end")).unwrap();
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

    let on_end: &Closure<dyn FnMut(wasm_bindgen::JsValue) -> JsValue> = {
        let res_ = res.clone();
        let symmetric_key = symmetric_key.clone();
        let next = js_sys::Function::from(next.clone());

        &Closure::new(move |_arg| {
            let raw_data = BODY.with(|body_| body_.take());

            let mut request = match process_data(&raw_data, &symmetric_key) {
                Ok(req) => req,
                Err(response) => {
                    js_sys::Reflect::set(&res_, &"statusCode".into(), &JsValue::from_f64(response.status as f64))
                        .expect("expected resp to be a mutable object");
                    js_sys::Reflect::set(&res_, &"statusMessage".into(), &JsValue::from_str(&response.status_text))
                        .expect("expected resp to be a mutable object");
                    return JsValue::NULL;
                }
            };

            js_sys::Reflect::set(&req, &"method".into(), &JsValue::from_str(&request.method)).expect("expected req to be a mutable object");
            for (header_key, header_val) in &request.headers {
                headers_map
                    .insert(header_key.clone(), JsWrapper::String(header_val.clone()))
                    .expect("expected headers to be a JsValue::Object; qed");
            }

            match request.headers.get("Content-Type") {
                // used for multipart form data
                Some(val) if val.to_lowercase().eq("application/layer8.buffer+json") => {
                    let req_body = serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&request.body)
                        .expect("expected req.body to be a valid json object");

                    // clear the body as it will be replaced by the formdata
                    request.body = Vec::new();

                    let url_path = get_url_path_from_body(&req_body).unwrap_or("".to_string());
                    js_sys::Reflect::set(&req, &"url".into(), &JsValue::from_str(&url_path)).expect("expected req to be a mutable object");

                    // pass in reqBody and get out a formData object
                    let form_data = match convert_body_to_form_data(&req_body) {
                        Ok(val) => val,
                        Err(err) => {
                            console_error(&format!("error decoding file buffer: {}", err));
                            js_sys::Reflect::set(&res_, &"statusCode".into(), &JsValue::from_f64(500.0))
                                .expect("expected resp to be a mutable object");
                            js_sys::Reflect::set(
                                &res_,
                                &"statusMessage".into(),
                                &JsValue::from_str(&format!("Could not decode file buffer: {}", err)),
                            )
                            .expect("expected resp to be a mutable object");
                            JsValue::NULL
                        }
                    };

                    let boundary = get_arbitrary_boundary();
                    request
                        .headers
                        .insert("Content-Type".to_string(), format!("multipart/form-data; boundary={boundary}"));
                    js_sys::Reflect::set(&req, &"body".into(), &form_data).expect("expected req to be a mutable object");
                }
                _ => {
                    match request.headers.get("Content-Type") {
                        Some(val) if val.is_empty() => {
                            request.headers.insert("Content-Type".to_string(), "application/json".to_string());
                        }
                        None => {
                            request.headers.insert("Content-Type".to_string(), "application/json".to_string());
                        }
                        _ => {}
                    }

                    let mut req_body = serde_json::from_slice::<HashMap<String, serde_json::Value>>(&request.body)
                        .expect("expected req.body to be a valid json object");

                    if let Some(val) = req_body.get("__url_path") {
                        let url_path = val.as_str().expect("expected url_path to be a string");
                        let parsed_url = url::Url::parse(url_path).expect("expected the url_path to be a valid url path, check the __url_path key");
                        let query_pairs: HashMap<_, _> = parsed_url.query_pairs().into_owned().collect();

                        let query = js_sys::Reflect::get(&req, &JsValue::from_str("query")).expect("expected req to have a query property");
                        for (key, val) in query_pairs {
                            js_sys::Reflect::set(&query, &JsValue::from_str(&key), &JsValue::from_str(&val))
                                .expect("expected req to be a mutable object");
                        }

                        // Remove __url_path from body
                        req_body.remove("__url_path").unwrap();
                    }

                    js_sys::Reflect::set(&req, &"body".into(), &JsValue::from(&serde_json::to_string(&req_body).unwrap()))
                        .expect("expected req to be a mutable object");
                }
            }

            next.call0(&JsValue::NULL).expect("expected next to be a function");
            JsValue::NULL
        })
    };

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
        let symmetric_key = symmetric_key.clone();
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
pub fn process_multipart(options: JsValue, _fs: JsValue) -> Object {
    let dest = js_sys::Reflect::get(&options, &JsValue::from_str("dest"))
        .expect("expected dest to be a property")
        .as_string()
        .expect("expected dest to be a string")
        .trim_matches('/')
        .to_string();

    let single = single_fn(JsValue::from_str(&dest));
    let array = array_fn(JsValue::from_str(&dest));

    let return_object = Object::new();
    let value = JsValue::from(&return_object);
    js_sys::Reflect::set(&value, &"single".into(), &single).unwrap();
    js_sys::Reflect::set(&value, &"array".into(), &array).unwrap();

    return_object
}

#[allow(non_snake_case)]
#[wasm_bindgen(js_name = ServerStatic)]
pub fn server_static(req: JsValue, res: JsValue, dir: JsValue, fs: JsValue) -> JsValue {
    let return_encrypted_image = |res: &JsValue| {
        let array_buffer = Uint8Array::from(encrypted_image::ENCRYPTED_IMAGE_DATA);

        js_sys::Reflect::set(res, &"statusCode".into(), &JsValue::from_f64(200.0)).expect("expected res to be a mutable object");
        js_sys::Reflect::set(res, &"statusMessage".into(), &JsValue::from_str("OK")).expect("expected res to be a mutable object");
        js_sys::Reflect::set(res, &"Content-Type".into(), &JsValue::from_str("image/png")).expect("expected res to be a mutable object");

        let end = js_sys::Reflect::get(res, &JsValue::from_str("end")).expect("expected res to have an end method");
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

    let mp_jwt = mp_jwt.unwrap_or_default(); // we could stick with Option but things become problematic with closures

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

        if !request.headers.contains_key("Content-Type") {
            request.headers.insert("Content-Type".to_string(), "application/json".to_string());
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

        let data = {
            let buff = read_file(&path_).expect("expected file to be read");
            let array_buffer = buff.obj.dyn_ref::<js_sys::ArrayBuffer>().unwrap();
            let array = js_sys::Uint8Array::new(array_buffer);
            array.to_vec()
        };

        let mime_type = data.sniff_mime_type().unwrap_or("application/octet-stream"); // TODO?
        let js_res = Response {
            body: data.clone(),
            status: 200,
            status_text: "OK".to_string(),
            headers: Vec::from([("Content-Type".to_string(), mime_type.to_string())]),
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
        set.call2(&JsValue::NULL, &JsValue::from_str("Content-Type"), &JsValue::from_str("application/json"))
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

fn get_url_path_from_body(req_body: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    for (_, v) in req_body {
        for val in v.as_array().expect("expected v to be an array") {
            let val = val.as_object().expect("expected val to be an object");
            if val
                .get("_type")
                .expect("expected val to have a _type key")
                .as_str()
                .expect("expected _type to be a string")
                == "String"
            {
                return Some(
                    val.get("value")
                        .expect("expected val to have a value key")
                        .as_str()
                        .expect("expected value to be a string")
                        .to_string(),
                );
            }
        }
    }

    None
}

fn convert_body_to_form_data(req_body: &serde_json::Map<String, serde_json::Value>) -> Result<JsValue, String> {
    let form_data = FormData::new().map_err(|err| {
        console_error(&format!("error creating form data {}", err.as_string().unwrap_or("".to_string())));
        "error creating form data".to_string()
    })?;

    let populate_form_data = |k: &str, val: &serde_json::Map<String, serde_json::Value>| {
        let _type = val
            .get("_type")
            .expect("expected val to have a _type key")
            .as_str()
            .expect("expected _type to be a string");

        match _type {
            x if x.eq("File") => {
                let buff = val
                    .get("buff")
                    .ok_or("expected File to have a buff key".to_string())?
                    .as_str()
                    .expect("expected value to be parsable as string");

                let name = val
                    .get("name")
                    .ok_or("expected File to have a name key".to_string())?
                    .as_str()
                    .expect("expected name to be parsable as string");

                let uint8_array = Uint8Array::from(buff.as_bytes());

                // find way to add type information to the file: TODO?
                let file = File::new_with_u8_array_sequence(&JsValue::from(&uint8_array), name).map_err(|err| {
                    console_error(&format!("error creating file: {}", err.as_string().unwrap_or("".to_string())));
                    "error creating file".to_string()
                })?;

                form_data.append_with_blob_and_filename(k, &file, name).map_err(|err| {
                    console_error(&format!(
                        "error appending file to form data: {}",
                        err.as_string().unwrap_or("".to_string())
                    ));
                    "error appending file to form data".to_string()
                })?;
            }

            x if x.eq("String") => form_data
                .append_with_str(k, x)
                .expect("expected form_data to be a mutable object and the key and value to be valid strings"),
            x if x.eq("Number") => {
                js_sys::Reflect::set(&form_data, &JsValue::from_str(k), &JsValue::from_f64(x.parse::<f64>().unwrap()))
                    .expect("expected form_data to be a mutable object");
            }
            x if x.eq("Boolean") => {
                js_sys::Reflect::set(&form_data, &JsValue::from_str(k), &JsValue::from_bool(x.parse::<bool>().unwrap()))
                    .expect("expected form_data to be a mutable object");
            }
            _ => {}
        }

        Ok::<(), String>(())
    };

    for (k, v) in req_body {
        if let serde_json::Value::Object(val) = v {
            populate_form_data(k, val)?;
        }
    }

    Ok(JsValue::from(form_data))
}

fn get_arbitrary_boundary() -> String {
    let mut small_rng = SmallRng::from_entropy();
    let random_bytes: [u8; 16] = small_rng.gen();
    format!("----Layer8FormBoundary{}", base64_enc_dec.encode(random_bytes))
}

#[cfg(test)]
mod tests {
    use js_sys::{Array, Function, Object};
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::*;
    use web_sys::File;

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

    #[test]
    fn test_get_arbitrary_boundary() {
        let boundary = super::get_arbitrary_boundary();
        assert!(boundary.starts_with("----Layer8FormBoundary"));
    }

    #[wasm_bindgen_test]
    fn test_process_multipart() {
        // let worker_handle = Worker::new("./worker.js").unwrap();

        let options = Object::new();
        js_sys::Reflect::set(&options, &"dest".into(), &JsValue::from_str("/tmp")).unwrap();
        let res = super::process_multipart(JsValue::from(options), JsValue::NULL);

        // call the single function
        let single = js_sys::Reflect::get(&res, &JsValue::from_str("single")).unwrap();
        let single = js_sys::Function::from(single);

        let req = {
            let req = Object::new();

            let file = sample_file();
            let body = Object::new();
            js_sys::Reflect::set(&body, &"file".into(), &file).unwrap();
            js_sys::Reflect::set(&req, &"body".into(), &JsValue::from(body)).unwrap();

            JsValue::from(req)
        };

        // noop next function
        let next = Function::new_no_args("console.log('next called on single')");

        let res = single.apply(&JsValue::NULL, &Array::from_iter([req, JsValue::NULL, next.into(), JsValue::NULL].iter()));

        match res {
            Ok(val) => {
                assert!(val.is_undefined());
            }
            Err(err) => {
                panic!("expected single to return an object: {:?}", err);
            }
        }
    }

    fn sample_file() -> File {
        let content = Array::new();
        content.push(&JsValue::from_str("foo"));
        let name = "foo.txt";
        let options = js_sys::Object::new();
        js_sys::Reflect::set(&options, &JsValue::from_str("type"), &JsValue::from_str("text/plain")).unwrap();
        web_sys::File::new_with_u8_array_sequence(&content, name).unwrap()
    }
}
