use std::{
    cell::{Cell, OnceCell},
    collections::HashMap,
    iter::Once,
};

use base64::{self, engine::general_purpose::URL_SAFE as base64_enc_dec, Engine as _};
use js_sys::{Array, Function, Object, Uint8Array};
use rand::{rngs::SmallRng, Rng, SeedableRng};
use serde_json::json;
use wasm_bindgen::prelude::*;
use web_sys::{File, FormData};

use layer8_interceptor_rs::{crypto::Jwk, types::Response};

use crate::{
    encrypted_image,
    internals::{self, process_data::process_data},
    js_wrapper::{self, to_value_from_js_value, JsWrapper, Type, Value},
    storage::INMEM_STORAGE_INSTANCE,
};

const VERSION: &str = "0.1.8";

thread_local! {
    static ModuleInitializedFn: OnceCell<()> = OnceCell::new();
}

// This imports are necessary, there's some type erasure working in the transformed Rust and or APIs transformed
// are not ported 1:1 from JS to Rust
#[wasm_bindgen(module = "/src/js_utility_functions.js")]
extern "C" {
    fn array_fn(dest: JsValue) -> Function;
    fn single_fn(dest: JsValue) -> Function;
    fn as_json_string(val: &JsValue) -> String;

    fn request_set_header(req: &JsValue, key: &str, val: &str);
    fn request_set_body(req: &JsValue, body: JsValue);
    fn request_set_url(req: &JsValue, url: &str);
    fn request_set_method(req: &JsValue, method: &str);
    fn request_get_url(req: &JsValue) -> JsValue;
    fn request_headers(req: &JsValue) -> JsValue;
    fn request_get_body_string(req: &JsValue) -> JsValue;
    fn request_callbacks(res: &JsValue, symmetric_key: JsValue, mp_jwt: JsValue, respond_callback: JsValue);

    fn request_add_on_end(req: &JsValue, end: JsValue);
    fn request_add_on_data(req: &JsValue, data: JsValue);

    fn response_add_header(res: &JsValue, key: &str, val: &str);
    fn response_set_status(res: &JsValue, status: u16);
    fn response_set_status_text(res: &JsValue, status_text: &str);
    fn response_set_body(res: &JsValue, body: &[u8]);
    fn response_get_headers(res: &JsValue) -> JsValue;
    fn response_get_status(res: &JsValue) -> JsValue;
    fn response_get_status_text(res: &JsValue) -> JsValue;
    fn response_end(res: &JsValue, body: JsValue);
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
}

#[allow(non_snake_case)]
#[wasm_bindgen(js_name = TestWASM)]
pub fn test_wasm() -> JsValue {
    JsValue::from_str("42")
}

#[allow(non_snake_case)]
#[wasm_bindgen(js_name = middleware_tester)]
pub fn middleware_tester(_req: JsValue, _res: JsValue, next: JsValue) {
    if let Err(err) = Function::from(next).call0(&JsValue::NULL) {
        console_error(&format!("Error invoking next middleware: {err:?}"));
    }
}

#[allow(non_snake_case)]
#[wasm_bindgen(js_name = tunnel)]
pub fn wasm_middleware(req: JsValue, res: JsValue, next: JsValue) {
    // getting the url
    log(&format!("URL: {}", request_get_url(&req).as_string().unwrap()));

    let headers_map = {
        let headers_object = Object::entries(&js_sys::Object::from(request_headers(&req)));
        
        let mut map = HashMap::new();
        for entry in headers_object.iter() {
            if entry.is_null() || entry.is_undefined() {
                // we skip null or undefined entries if any
                continue;
            }

            // [key, value]
            let key_val_entry = Array::from(&entry);
            let key = match key_val_entry.get(0).as_string() {
                Some(val) => val,
                None => {
                    console_error(&format!("Error accessing headers"));
                    // invoking next middleware
                    if let Err(e) = js_sys::Function::from(next).call0(&JsValue::NULL) {
                        console_error(&format!("Error invoking next middleware: {e:?}"));
                    }
                    return;
                }
            };

            if let Ok(val) = to_value_from_js_value(&key_val_entry.get(1)) {
                map.insert(key, val.value);
            }
        }

        map
    };

    if !headers_map.contains_key("x-tunnel")
        || headers_map.get("x-tunnel") == Some(&JsWrapper::String("".to_string()))
        || headers_map.get("x-tunnel") == Some(&JsWrapper::Undefined)
        || headers_map.get("x-tunnel") == Some(&JsWrapper::Null)
    {
        // invoking next middleware
        if let Err(e) = js_sys::Function::from(next).call0(&JsValue::NULL) {
            console_error(&format!("Error invoking next middleware: {e:?}"));
        }
        return;
    }

    let init_ecdh = |resp: &JsValue| {
        let res = INMEM_STORAGE_INSTANCE.with(|storage| {
            let mut inmem_storage = storage.take();
            let res = internals::init_ecdh::initialize_ecdh(
                Value {
                    r#type: js_wrapper::Type::Object,
                    constructor: "Object".to_string(),
                    value: JsWrapper::Object(headers_map.clone()),
                },
                &mut inmem_storage,
            );

            storage.replace(inmem_storage);
            res
        });

        match res {
            Ok(res) => {
                log("ECDH Successfully Completed!");
                response_set_status(resp, 200);
                response_set_status_text(resp, "ECDH Successfully Completed!");
                response_add_header(resp, "mp-JWT", &res.mp_jwt);
                response_add_header(resp, "server_pubKeyECDH", &res.server_public_key);
            }
            Err(err) => {
                console_error(&err);
                response_set_status(resp, 500);
                response_set_status_text(resp, "Failure to initialize ECDH");
            }
        }
    };

    let is_ecdh_init = headers_map.get("x-ecdh-init");
    let client_uuid = headers_map.get("x-client-uuid");
    if client_uuid.is_none()
        || (is_ecdh_init.is_some() && *is_ecdh_init.unwrap() != JsWrapper::Null)
        || (is_ecdh_init.is_some() && *is_ecdh_init.unwrap() != JsWrapper::Undefined)
    {
        init_ecdh(&res);

        // invoking next middleware
        if let Err(e) = js_sys::Function::from(next).call0(&JsValue::NULL) {
            console_error(&format!("Error invoking next middleware: {e:?}"));
        }
        return;
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

                // invoking next middleware
                if let Err(e) = js_sys::Function::from(next).call0(&JsValue::NULL) {
                    console_error(&format!("Error invoking next middleware: {e:?}"));
                }
                return;
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

                // invoking next middleware
                if let Err(e) = js_sys::Function::from(next).call0(&JsValue::NULL) {
                    console_error(&format!("Error invoking next middleware: {e:?}"));
                }
                return;
            }
        }
    };

    let sym_key = serde_json::to_string(&symmetric_key)
        .map(|val| JsValue::from_str(&val))
        .expect("expected symmetric key to be serializable to a string; qed");
    let jwt = JsValue::from_str(&mp_jwt);
    let respond_callback_: Closure<dyn Fn(JsValue, JsValue, JsValue, JsValue)> = Closure::new(|res, data, sym_key, jwt| {
        respond_callback(&res, &data, sym_key, jwt);
    });
    request_callbacks(&res, sym_key, jwt, respond_callback_.into_js_value());

    // we are not waiting for the `on end event` and `on data event` to be called; still figuring how to work that in in a way that works
    let body = match request_get_body_string(&req).as_string() {
        Some(val) => val,
        None => {
            console_error("expected body to be a string");
            // invoking next middleware
            if let Err(e) = js_sys::Function::from(next).call0(&JsValue::NULL) {
                console_error(&format!("Error invoking next middleware: {e:?}"));
            }
            return;
        }
    };

    match process_data(&body, &symmetric_key) {
        Ok(processed_req) => {
            log("Successfully processed data!");

            // propagate the request's original method
            request_set_method(&req, &processed_req.method);

            let mut req_body = match serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&processed_req.body) {
                Ok(val) => val,
                Err(err) => {
                    if !processed_req.body.is_empty() {
                        console_error(&format!("error decoding body: {}", err));
                        response_set_status(&res, 500);
                        response_set_body(&res, b"error decoding body");

                        // invoking next middleware
                        if let Err(e) = js_sys::Function::from(next).call0(&JsValue::NULL) {
                            console_error(&format!("Error invoking next middleware: {e:?}"));
                        }
                        return;
                    }

                    serde_json::Map::new()
                }
            };

            match processed_req.headers.get("content-type") {
                Some(x) if x.eq("application/layer8.buffer+json") => {
                    let url_ = match get_url_path_from_body(&req_body) {
                        Some(val) => val,
                        None => {
                            console_error("expected the body to have a __url_path key, this is used to determine the url path for the request");
                            response_set_status(&res, 500);
                            response_set_body(
                                &res,
                                b"expected the body to have a __url_path key, this is used to determine the url path for the request",
                            );

                            // invoking next middleware
                            if let Err(e) = js_sys::Function::from(next).call0(&JsValue::NULL) {
                                console_error(&format!("Error invoking next middleware: {e:?}"));
                            }
                            return;
                        }
                    };

                    request_set_url(&req, &url_);

                    let form_data = match convert_body_to_form_data(&req_body) {
                        Ok(val) => val,
                        Err(err) => {
                            console_error(&format!("error decoding file buffer: {}", err));
                            response_set_status_text(&res, &format!("Could not decode file buffer: {}", err));
                            response_set_status(&res, 500);

                            console_error("expected the body to have a __url_path key, this is used to determine the url path for the request");
                            // invoking next middleware
                            if let Err(e) = js_sys::Function::from(next).call0(&JsValue::NULL) {
                                console_error(&format!("Error invoking next middleware: {e:?}"));
                            }
                            return;
                        }
                    };

                    let boundary = get_arbitrary_boundary();
                    request_set_header(&req, "content-type", &format!("multipart/form-data; boundary={}", boundary));
                    request_set_body(&req, form_data);
                }

                _ => {
                    if let Some(val) = req_body.get("__url_path") {
                        let url_path = match val.as_str() {
                            Some(val) => val,
                            None => {
                                console_error("expected the __url_path key to be a string");
                                response_set_status(&res, 500);
                                response_set_body(&res, b"expected the __url_path key to be a string");

                                // invoking next middleware
                                if let Err(e) = js_sys::Function::from(next).call0(&JsValue::NULL) {
                                    console_error(&format!("Error invoking next middleware: {e:?}"));
                                }
                                return;
                            }
                        };

                        let mut parsed_url = match url::Url::parse(url_path) {
                            Ok(val) => val,
                            Err(err) => {
                                console_error(&format!("error parsing url: {}", err));
                                response_set_status(&res, 500);
                                response_set_body(&res, b"error parsing url");

                                // invoking next middleware
                                if let Err(e) = js_sys::Function::from(next).call0(&JsValue::NULL) {
                                    console_error(&format!("Error invoking next middleware: {e:?}"));
                                }
                                return;
                            }
                        };

                        let query_pairs: HashMap<_, _> = parsed_url.query_pairs().into_owned().collect();
                        let query = form_urlencoded::Serializer::new(String::new()).extend_pairs(query_pairs.iter()).finish();
                        parsed_url.set_query(Some(&query));
                        request_set_url(&req, url_path);

                        // rm __url_path from body
                        req_body.remove("__url_path").unwrap();
                    }

                    if !processed_req.body.is_empty() {
                        request_set_body(&req, JsValue::from_str(&String::from_utf8_lossy(&processed_req.body)));
                    }
                }
            }
        }
        Err(processed_resp) => {
            log("Issue processing data!");
            response_set_status(&res, processed_resp.status);
            response_set_status_text(&res, &processed_resp.status_text);
        }
    }

    // invoking next middleware
    if let Err(e) = js_sys::Function::from(next).call0(&JsValue::NULL) {
        console_error(&format!("Error invoking next middleware: {e:?}"));
    }
}

pub fn respond_callback(res: &JsValue, data: &JsValue, sym_key: JsValue, jwt: JsValue) {
    let sym_key = serde_json::from_str::<Jwk>(&sym_key.as_string().expect("expected sym_key to be a string"))
        .expect("expected sym_key to be a valid json object; qed"); // infalliable, we know the data is a valid json object

    let mut data_ = Vec::new();
    if data.is_string() {
        data_ = data.as_string().expect("expected data to be a string").as_bytes().to_vec();
    } else if data.is_object() {
        data_ = as_json_string(&data).as_bytes().to_vec();
    } else {
        console_error(&format!("expected data to be a string or an object, have: {:?}", data));
    }

    let resp = prepare_data(&res, &data_, &sym_key, &jwt.as_string().expect("expected jwt to be a string"));
    response_set_status(&res, resp.status);
    response_set_status_text(&res, &resp.status_text);
    for (key, val) in resp.headers {
        response_add_header(&res, &key, &val);
    }

    let data = json!({
        "data": base64_enc_dec.encode(&resp.body).to_string(),
    })
    .to_string();

    response_end(&res, JsValue::from_str(&data));
}

#[allow(non_snake_case)]
#[wasm_bindgen(js_name = ProcessMultipart)]
pub fn process_multipart(options: JsValue, _fs: JsValue) -> Object {
    let dest = {
        let dest = js_sys::Reflect::get(&options, &JsValue::from_str("dest"))
            .expect("expected dest to be a property")
            .as_string()
            .expect("expected dest to be a string")
            .trim_matches('/')
            .to_string();
        JsValue::from_str(&dest)
    };

    let single = single_fn(dest.clone());
    let array = array_fn(dest);

    let return_object = Object::new();
    let value = JsValue::from(&return_object);
    js_sys::Reflect::set(&value, &"single".into(), &single).unwrap();
    js_sys::Reflect::set(&value, &"array".into(), &array).unwrap();

    return_object
}

#[allow(non_snake_case)]
#[wasm_bindgen(js_name = _static)]
pub fn _static(dir: JsValue) -> JsValue {
    let higher_order_fn: Closure<dyn Fn(wasm_bindgen::JsValue, wasm_bindgen::JsValue, wasm_bindgen::JsValue)> =
        Closure::new(move |req, res, next| {
            server_static(&req, &res, dir.clone());

            // invoking next middleware
            if let Err(e) = js_sys::Function::from(next).call0(&JsValue::NULL) {
                console_error(&format!("Error invoking next middleware: {e:?}"));
            }
            return;
        });
    higher_order_fn.into_js_value()
}

fn server_static(req: &JsValue, res: &JsValue, dir: JsValue) {
    let return_encrypted_image = |res: &JsValue| {
        let array_buffer = Uint8Array::from(encrypted_image::ENCRYPTED_IMAGE_DATA);
        response_set_status(&res, 200);
        response_set_status_text(&res, "OK");
        response_add_header(&res, "content-type", "image/png");
        response_end(res, array_buffer.into());
    };

    let headers =
        to_value_from_js_value(&js_sys::Reflect::get(&req, &JsValue::from_str("headers")).expect("expected req to have a headers property"))
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

    // let add_event_listener = js_sys::Function::from(
    //     js_sys::Reflect::get(&req, &JsValue::from_str("addEventListener")).expect("expected req to have an addEventListener method"),
    // );

    // end event listener
    // let on_end: Closure<dyn FnMut(wasm_bindgen::JsValue) -> JsValue> = {
    //     let mp_jwt = mp_jwt.clone();
    //     Closure::new(move |_arg| {
    //         let body = BODY.with(|body_| body_.take());

    //         let mut request = match process_data(&body, &symmetric_key) {
    //             Ok(request) => request,
    //             Err(response) => {
    //                 js_sys::Reflect::set(&res, &"statusCode".into(), &JsValue::from_f64(response.status as f64))
    //                     .expect("expected res to be a mutable object");
    //                 js_sys::Reflect::set(&res, &"statusMessage".into(), &JsValue::from_str(&response.status_text))
    //                     .expect("expected res to be a mutable object");

    //                 return JsValue::NULL;
    //             }
    //         };

    //         js_sys::Reflect::set(&req, &"method".into(), &JsValue::from_str(&request.method)).expect("expected req to be a mutable object");

    //         for (header_key, header_val) in &request.headers {
    //             headers
    //                 .set(&header_key.clone(), JsWrapper::String(header_val.clone()))
    //                 .expect("expected headers to be a JsValue::Object; qed");
    //         }

    //         if !request.headers.contains_key("Content-Type") {
    //             request.headers.insert("Content-Type".to_string(), "application/json".to_string());
    //         }

    //         let mut body =
    //             serde_json::from_slice::<HashMap<String, serde_json::Value>>(&request.body).expect("expected req.body to be a valid json object");

    //         if let Some(url_path) = body.get("__url_path") {
    //             let url_path = url_path.as_str().expect("expected url_path to be a string");
    //             let parsed_url = url::Url::parse(url_path).expect("expected the url_path to be a valid url path, check the __url_path key");
    //             let query_pairs: HashMap<_, _> = parsed_url.query_pairs().into_owned().collect();

    //             let query = js_sys::Reflect::get(&req, &JsValue::from_str("query")).expect("expected req to have a query property");
    //             for (key, val) in query_pairs {
    //                 js_sys::Reflect::set(&query, &JsValue::from_str(&key), &JsValue::from_str(&val)).expect("expected req to be a mutable object");
    //             }
    //             body.remove("__url_path").unwrap();
    //         }

    //         // getting the file path
    //         let path = {
    //             let mut path = js_sys::Reflect::get(&req, &JsValue::from_str("url"))
    //                 .expect("expected req to have a url property")
    //                 .as_string()
    //                 .expect("expected url to be a string");
    //             if path.eq("/") {
    //                 path = "/index.html".to_string();
    //             }

    //             path
    //         };

    //         let path = match url::form_urlencoded::parse(path.as_bytes()).next() {
    //             Some((key, val)) => format!("{key}={val}"), // validate!
    //             None => {
    //                 js_sys::Reflect::set(&res, &"statusCode".into(), &JsValue::from_f64(500.0)).expect("expected res to be a mutable object");
    //                 js_sys::Reflect::set(&res, &"statusMessage".into(), &JsValue::from_str("Internal Server Error"))
    //                     .expect("expected res to be a mutable object");

    //                 let end = js_sys::Reflect::get(&res, &JsValue::from_str("end")).expect("expected res to have an end method");
    //                 let end = js_sys::Function::from(end);
    //                 end.call1(&JsValue::NULL, &JsValue::from_str("500 Internal Server Error_2"))
    //                     .expect("expected end to be a function");

    //                 todo!(); // resytucvure o return on error
    //             }
    //         };

    //         // let path_ = dir.as_string().expect("expected the dir to be a string; qed") + &path;

    //         // let exists_sync = js_sys::Reflect::get(&fs, &JsValue::from_str("existsSync")).expect("expected fs to have an existsSync method");
    //         // // let exists_sync = js_sys::Function::from(exists_sync);
    //         // let exists = exists_sync
    //         //     .call1(&JsValue::NULL, &JsValue::from_str(&path_))
    //         //     .expect("expected existsSync to be a function")
    //         //     .as_bool()
    //         //     .expect("expected existsSync to return a boolean");

    //         if !false {
    //             js_sys::Reflect::set(&res, &"statusCode".into(), &JsValue::from_f64(404.0)).expect("expected res to be a mutable object");
    //             js_sys::Reflect::set(&res, &"statusMessage".into(), &JsValue::from_str("Not Found")).expect("expected res to be a mutable object");

    //             let end = js_sys::Reflect::get(&res, &JsValue::from_str("end")).expect("expected res to have an end method");
    //             let end = js_sys::Function::from(end);
    //             end.call1(&JsValue::NULL, &JsValue::from_str(&format!("Cannot GET {path}")))
    //                 .expect("expected end to be a function");

    //             todo!()
    //         }

    //         // return the default EncryptedImageData if the request is not a layer8 request
    //         if headers.is_null() || headers.is_undefined() || {
    //             if let Ok(val) = headers.get("x-tunnel") {
    //                 if let Some(val) = val {
    //                     *val == JsWrapper::Undefined || *val == JsWrapper::Null
    //                 } else {
    //                     true
    //                 };
    //             }
    //             true
    //         } {
    //             return_encrypted_image(&res);
    //         }

    //         let data = {
    //             // let buff = read_file(&path_).expect("expected file to be read");
    //             // let array_buffer = buff.obj.dyn_ref::<js_sys::ArrayBuffer>().unwrap();
    //             // let array = js_sys::Uint8Array::new(array_buffer);
    //             // array.to_vec()

    //             Vec::new() // todo1()
    //         };

    //         let mime_type = data.sniff_mime_type().unwrap_or("application/octet-stream"); // TODO?
    //         let js_res = Response {
    //             body: data.clone(),
    //             status: 200,
    //             status_text: "OK".to_string(),
    //             headers: Vec::from([("Content-Type".to_string(), mime_type.to_string())]),
    //         };

    //         // encrypt the file
    //         let encrypted = match symmetric_key
    //             .symmetric_encrypt(&serde_json::to_vec(&js_res).expect("expected the response to be serializable to a valid json object; qed"))
    //         {
    //             Ok(val) => val,
    //             Err(err) => {
    //                 console_error(&format!("error encrypting file: {err}"));

    //                 js_sys::Reflect::set(&res, &"statusCode".into(), &JsValue::from_f64(500.0)).expect("expected res to be a mutable object");
    //                 js_sys::Reflect::set(&res, &"statusMessage".into(), &JsValue::from_str("Internal Server Error"))
    //                     .expect("expected res to be a mutable object");

    //                 let end = js_sys::Reflect::get(&res, &JsValue::from_str("end")).expect("expected res to have an end method");
    //                 let end = js_sys::Function::from(end);
    //                 end.call1(&JsValue::NULL, &JsValue::from_str("500 Internal Server Error_1"))
    //                     .expect("expected end to be a function");

    //                 return JsValue::NULL;
    //             }
    //         };

    //         // sending the response
    //         js_sys::Reflect::set(&res, &"statusCode".into(), &JsValue::from_f64(js_res.status as f64)).expect("expected res to be a mutable object");
    //         js_sys::Reflect::set(&res, &"statusMessage".into(), &JsValue::from_str(&js_res.status_text))
    //             .expect("expected res to be a mutable object");

    //         let set = js_sys::Reflect::get(&res, &JsValue::from_str("set")).unwrap();
    //         let set = js_sys::Function::from(set);
    //         set.call2(&JsValue::NULL, &JsValue::from_str("Content-Type"), &JsValue::from_str("application/json"))
    //             .expect("expected set to be a function");

    //         set.call2(&JsValue::NULL, &JsValue::from_str("mp-JWT"), &JsValue::from_str(&mp_jwt))
    //             .expect("expected set to be a function");

    //         let end = js_sys::Reflect::get(&res, &JsValue::from_str("end")).unwrap();
    //         let end = js_sys::Function::from(end);

    //         let data = Object::new();
    //         js_sys::Reflect::set(&data, &"data".into(), &JsValue::from_str(&base64_enc_dec.encode(&encrypted)))
    //             .expect("expected data to be a mutable object");

    //         end.call1(&JsValue::NULL, &JsValue::from(data)).expect("expected end to be a function");

    //         JsValue::NULL
    //     })
    // };
    // request_add_on_end(&req, on_end.into_js_value());
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

// modded from to_value_from_js_value, FIXME: refactor
pub fn parse_req_to_value(js_value: &JsValue, recurse: bool) -> Result<Value, String> {
    // Null
    if js_value.is_null() {
        return Ok(Value {
            r#type: Type::Null,
            constructor: "Null".to_string(),
            value: JsWrapper::Null,
        });
    }

    // Undefined
    if js_value.is_undefined() {
        return Ok(Value {
            r#type: Type::Undefined,
            constructor: "Undefined".to_string(),
            value: JsWrapper::Undefined,
        });
    }

    // Number
    if let Some(val) = js_value.as_f64() {
        return Ok(Value {
            r#type: Type::Number,
            constructor: "Number".to_string(),
            value: JsWrapper::Number(val),
        });
    }

    // Boolean
    if let Some(val) = js_value.as_bool() {
        return Ok(Value {
            r#type: Type::Boolean,
            constructor: "Boolean".to_string(),
            value: JsWrapper::Boolean(val),
        });
    }

    // String
    if js_value.is_string() {
        return Ok(Value {
            r#type: Type::String,
            constructor: "String".to_string(),
            value: JsWrapper::String(js_value.as_string().expect("expected the value to be a string; qed")),
        });
    }

    // Array; we parse the array first before the object since an array is an object
    if js_value.is_array() {
        let arr = Array::from(js_value);
        let mut vec = Vec::new();
        for elem in arr {
            if let Ok(val) = parse_req_to_value(&elem, true) {
                vec.push(val.value);
            }
        }

        if vec.is_empty() {
            return Ok(Value {
                r#type: Type::Null,
                constructor: "Null".to_string(),
                value: JsWrapper::Null,
            });
        }

        return Ok(Value {
            r#type: Type::Array,
            constructor: "Array".to_string(),
            value: JsWrapper::Array(vec),
        });
    }

    // Object
    if js_value.is_object() {
        // [[key, value],...]  2d array
        let req_object = {
            let val = Object::try_from(js_value).expect("expected the req to be an object; qed");
            Object::entries(val)
        };

        let mut map = HashMap::new();
        for entry in req_object.iter() {
            if entry.is_null() || entry.is_undefined() {
                // we skip null or undefined entries if any
                continue;
            }

            // [key, value]
            let key_val_entry = Array::from(&entry);
            let key = match key_val_entry.get(0) {
                val if val.is_undefined() || val.is_null() => continue,
                val => val.as_string().expect("expected the key to be a string; qed"),
            };

            // for everyone's sanity we are only going to recurse if the key is `body`
            if recurse || key.eq_ignore_ascii_case("body") || key.eq_ignore_ascii_case("headers") || key.eq_ignore_ascii_case("rawHeaders") {
                match key_val_entry.get(1) {
                    val if val.is_undefined() || val.is_null() => continue,
                    val => {
                        if let Ok(val) = parse_req_to_value(&val, true) {
                            map.insert(key, val.value);
                        }
                    }
                }
            }
        }

        return Ok(Value {
            r#type: Type::Object,
            constructor: "Object".to_string(),
            value: JsWrapper::Object(map),
        });
    }

    Err("Unknown type".to_string())
}

pub fn prepare_data(res: &JsValue, data: &[u8], sym_key: &Jwk, jwt: &str) -> Response {
    let mut js_response = Response {
        body: Vec::from(data),
        status: 200,
        ..Default::default()
    };

    if let Some(status) = response_get_status(res).as_f64() {
        js_response.status = status as u16;
    }

    if let Some(status_text) = response_get_status_text(res).as_string() {
        js_response.status_text = status_text;
    }

    js_response.headers = {
        let mut headers = Vec::new();
        let headers_ = response_get_headers(res);
        if !headers_.is_null() && !headers_.is_undefined() {
            let headers_object = Object::entries(&js_sys::Object::from(headers_));

            for entry in headers_object.iter() {
                if entry.is_null() || entry.is_undefined() {
                    // we skip null or undefined entries if any
                    continue;
                }

                // [key, value]
                let key_val_entry = Array::from(&entry);
                let key = key_val_entry.get(0).as_string().expect("expected key to be a string; qed");
                if let Ok(val) = to_value_from_js_value(&key_val_entry.get(1)) {
                    headers.push((key.clone(), val.value.to_string().expect("expected value to be a string; qed")));
                }
            }
        }

        headers
    };

    let body = sym_key
        .symmetric_encrypt(&serde_json::to_vec(&js_response).expect("the type implements Serialize"))
        .expect("no internal errors expected on encryption");

    Response {
        body,
        status: js_response.status,
        status_text: js_response.status_text,
        headers: vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("mp-JWT".to_string(), jwt.to_string()),
        ],
    }
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
        let options = Object::new();
        js_sys::Reflect::set(&options, &"dest".into(), &JsValue::from_str("/tmp")).unwrap();
        let res = super::process_multipart(JsValue::from(options), JsValue::NULL);

        // call the array function
        {
            let array = js_sys::Reflect::get(&res, &JsValue::from_str("array")).unwrap();
            let array = js_sys::Function::from(array);
            let req = {
                let req = Object::new();
                let file1 = sample_file("foo.txt");
                let file2 = sample_file("bar.txt");

                let files = Array::from_iter([file1, file2].iter());

                let body = Object::new();
                js_sys::Reflect::set(&body, &"file".into(), &files).unwrap();
                js_sys::Reflect::set(&req, &"body".into(), &JsValue::from(body)).unwrap();

                JsValue::from(req)
            };

            // noop next function
            let next = Function::new_no_args("console.log('next called on array')");
            let res = array.apply(&JsValue::NULL, &Array::from_iter([req, JsValue::NULL, next.into(), JsValue::NULL].iter()));

            match res {
                Ok(val) => {
                    assert!(val.is_undefined());
                }
                Err(err) => {
                    panic!("expected single to return an object: {:?}", err);
                }
            }
        }

        // call the single function
        {
            let single = js_sys::Reflect::get(&res, &JsValue::from_str("single")).unwrap();
            let single = js_sys::Function::from(single);

            let req = {
                let req = Object::new();

                let file = sample_file("foo.txt");
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
    }

    fn sample_file(name: &str) -> File {
        let content = Array::new();
        content.push(&JsValue::from_str("foo"));
        let options = js_sys::Object::new();
        js_sys::Reflect::set(&options, &JsValue::from_str("type"), &JsValue::from_str("text/plain")).unwrap();
        web_sys::File::new_with_u8_array_sequence(&content, name).unwrap()
    }

    #[wasm_bindgen_test]
    fn test_try_into() {
        let val = crate::middleware::to_value_from_js_value(&{
            let obj = Object::new();
            JsValue::from(obj)
        })
        .unwrap();
        assert_eq!(*val.get_type(), crate::js_wrapper::Type::Object);
    }
}
