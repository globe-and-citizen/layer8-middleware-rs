use std::collections::HashMap;

use base64::{self, engine::general_purpose::URL_SAFE as base64_enc_dec, Engine as _};
use js_sys::{Array, Function, Object, Uint8Array};
use mime_sniffer::MimeTypeSniffer;
use rand::{rngs::SmallRng, Rng, SeedableRng};
use serde_json::json;
use url::Url;
use wasm_bindgen::prelude::*;
use web_sys::{File, FormData};

use layer8_primitives::{
    crypto::Jwk,
    types::{Response, ServeStatic},
};

use crate::{
    encrypted_image,
    internals::{self, process_data::process_data},
    js_wrapper::{self, custom_js_imports::*, to_value_from_js_value, AssetsFunctionsWrapper, JsWrapper, Type, Value},
    storage::INMEM_STORAGE_INSTANCE,
};

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

#[wasm_bindgen(module = "fs")]
extern "C" {
    #[wasm_bindgen(js_name = readFileSync, catch)]
    fn read_file(path: &str) -> Result<Buffer, JsValue>;

    #[wasm_bindgen(js_name = existsSync, catch)]
    fn exists_sync(path: &str) -> Result<bool, JsValue>;
}

/// This function is a middleware that is used to initialize the ECDH key exchange between the client and the server.
#[allow(non_snake_case)]
#[wasm_bindgen(js_name = tunnel)]
pub fn wasm_middleware(req: JsValue, res: JsValue, next: JsValue) {
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
                    console_error("Error accessing headers");
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
                response_set_body_end(resp, res.server_public_key.as_bytes());
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
        || (is_ecdh_init.is_some() && *is_ecdh_init.expect_throw("infalliable") != JsWrapper::Null)
        || (is_ecdh_init.is_some() && *is_ecdh_init.expect_throw("infalliable") != JsWrapper::Undefined)
    {
        init_ecdh(&res);

        // invoking next middleware
        if let Err(e) = js_sys::Function::from(next).call0(&JsValue::NULL) {
            console_error(&format!("Error invoking next middleware: {e:?}"));
        }
        return;
    }

    let client_uuid = client_uuid
        .expect_throw("infalliable")
        .to_string()
        .expect_throw("expected client_uuid to be a string; qed");

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

    let sym_key = serde_json::to_string(&symmetric_key).expect("expected symmetric key to be serializable to a string; qed");
    let respond_callback_: Closure<dyn Fn(JsValue, JsValue, String, String)> = Closure::new(|res, data, sym_key, jwt| {
        respond_callback(&res, &data, sym_key, jwt);
    });
    request_callbacks(&res, &sym_key, &mp_jwt, respond_callback_.into_js_value());

    let body = match request_get_body(&req) {
        Ok(val) => {
            // we expect the body to be an Object
            as_json_string(&val)
        }
        Err(err) => {
            // this is not supposed to happen; signal that the data aggregation for the body is supposed to be
            // called before the tunnel is invoked
            console_error("The middleware expects the body to be aggregated before the tunnel is invoked: call `app.use(express.json({limit: '100mb'}))` with a sane limit");
            if !err.is_null() && !err.is_undefined() {
                console_error(&format!("Error reading body: {:?}", err));
            }

            // handing over to the server logic
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

            // propagate the request's original url
            if let Some(val) = processed_req.url_path {
                log(&format!("Parsed URL: {}", val));
                request_set_url(&req, &val);
            }

            // we assume all data to and fro will be JSON, we have to account for other data formats; TODO @osoro
            // Provide allowance for custom user defined extensions?
            let req_body = match serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&processed_req.body) {
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
                    if processed_req.body.is_empty() {
                        request_set_body(&req, JsValue::null());
                    } else {
                        request_set_body(
                            &req,
                            JsValue::from(
                                &serde_json::to_string(&req_body).expect_throw("expected the body to be serializable to a valid json object; qed"),
                            ),
                        );
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

fn respond_callback(res: &JsValue, data: &JsValue, sym_key: String, jwt: String) {
    let sym_key = serde_json::from_str::<Jwk>(&sym_key).expect_throw("expected sym_key to be a valid json object; qed"); // infalliable, we know the data is a valid json object

    let mut data_ = Vec::new();
    if data.is_string() {
        data_ = data.as_string().expect_throw("expected data to be a string").as_bytes().to_vec();
    } else if data.is_object() {
        data_ = as_json_string(data).as_bytes().to_vec();
    } else {
        console_error(&format!("expected data to be a string or an object, have: {:?}", data));
    }

    let resp = prepare_data(res, &data_, &sym_key, &jwt);
    response_set_status(res, resp.status);
    response_set_status_text(res, &resp.status_text);
    for (key, val) in resp.headers {
        response_add_header(res, &key, &val);
    }

    let data = json!({
        "data": base64_enc_dec.encode(&resp.body).to_string(),
    })
    .to_string();

    response_set_body_end(res, data.as_bytes());
}

/// This function processes the multipart form data, it returns an object with two functions: `single` and `array`
/// `single` is used to process a single file upload
/// `array` is used to process multiple file uploads
/// The `dest` parameter is the destination where the files will be saved. The destination is expected to be a string.
#[allow(non_snake_case)]
#[wasm_bindgen(js_name = multipart)]
pub fn process_multipart(options: JsValue) -> AssetsFunctionsWrapper {
    let dest = {
        let dest = js_sys::Reflect::get(&options, &JsValue::from_str("dest"))
            .expect_throw("expected dest to be a property")
            .as_string()
            .expect_throw("expected dest to be a string")
            .trim_matches('/')
            .to_string();
        JsValue::from_str(&dest)
    };

    let single = single_fn(dest.clone());
    let array = array_fn(dest);

    AssetsFunctionsWrapper {
        single: Function::from(single),
        array: Function::from(array),
    }
}

/// This function is responsible for serving static files, it takes the resource directory as an argument.
/// The resource directory is expected to be a string.
#[allow(non_snake_case)]
#[wasm_bindgen(js_name = static)]
pub fn _static(dir: String) -> JsValue {
    let higher_order_fn: Closure<dyn Fn(wasm_bindgen::JsValue, wasm_bindgen::JsValue, wasm_bindgen::JsValue)> =
        Closure::new(move |req, res, next| {
            log("calling serve static");
            serve_static(&req, &res, dir.clone());

            // invoking next middleware
            if let Err(e) = js_sys::Function::from(next).call0(&JsValue::NULL) {
                console_error(&format!("Error invoking next middleware: {e:?}"));
            }
        });

    higher_order_fn.into_js_value()
}

fn serve_static(req: &JsValue, res: &JsValue, dir: String) {
    let return_encrypted_image = |res: &JsValue| {
        response_set_status(res, 200);
        response_set_status_text(res, "OK");
        response_add_header(res, "content-type", "image/png");
        response_set_body_end(res, encrypted_image::ENCRYPTED_IMAGE_DATA);
    };

    let headers_map = {
        let headers_object = Object::entries(&js_sys::Object::from(request_headers(req)));

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
                    console_error("Error reading header key");
                    return return_encrypted_image(res);
                }
            };

            let value = match key_val_entry.get(1).as_string() {
                Some(val) => val,
                None => {
                    console_error("Error reading header value");
                    return return_encrypted_image(res);
                }
            };

            map.insert(key.to_lowercase().trim().to_string(), value);
        }

        map
    };

    let client_uuid = match headers_map.get("x-client-uuid") {
        Some(val) => val,
        None => {
            return return_encrypted_image(res);
        }
    };

    let (mp_jwt, symmetric_key) = INMEM_STORAGE_INSTANCE.with(|val| {
        let val_ = val.take();
        val.replace(val_.clone());
        (val_.jwts.get(client_uuid).cloned(), val_.keys.get(client_uuid).cloned())
    });

    let symmetric_key = match symmetric_key {
        Some(val) => val,
        None => return return_encrypted_image(res),
    };

    let mp_jwt = match mp_jwt {
        Some(val) => val,
        None => {
            console_error("Could not find `mp_jwt` on inmem storage");
            return return_encrypted_image(res);
        }
    };

    let resource_url = {
        let val = &request_get_body(req)
            .map_err(|e| {
                console_error(&format!("Error reading body: {e:?}"));
            })
            .expect_throw("expected the body to have data; qed");

        // We expect a continuous u8 byte sequence that can be converted to a string
        let payload = serde_json::from_str::<ServeStatic>(&val.as_string().expect_throw("expected the body to be a string; qed"))
            .expect_throw("expected the body to be a valid json; qed");
        payload.__url_path
    };

    let parsed_url = url::Url::parse(&resource_url).expect("expected the url_path to be a valid url path, check the __url_path key");

    let query_pairs: HashMap<_, _> = parsed_url.query_pairs().into_owned().collect();

    let query = js_sys::Reflect::get(req, &JsValue::from_str("query")).expect("expected req to have a query property");

    for (key, val) in query_pairs {
        js_sys::Reflect::set(&query, &JsValue::from_str(&key), &JsValue::from_str(&val)).expect("expected req to be a mutable object");
    }

    request_set_body(req, JsValue::null());

    // getting the file path
    let path = {
        let url = Url::parse(&resource_url).expect_throw("expected the url_path to be a valid url path, check the __url_path key");
        let mut path = url.path().to_string();
        if path.eq("/") {
            path = "/index.html".to_string();
        }

        path
    };

    let mut path = match url::form_urlencoded::parse(path.as_bytes()).next() {
        Some((key, val)) => {
            if val.is_empty() {
                key.to_string()
            } else {
                format!("{key}={val}")
            }
        }
        None => {
            log(&format!("expected the path to be a valid url path: {}", path));
            response_set_status(res, 500);
            response_set_status_text(res, "Internal Server Error");
            return response_set_body_end(res, b"500 Internal Server Error 1");
        }
    };

    // we don't want to hardcode any paths but if on first try we do not get the path, it's time to truncate the sub-paths
    // until we are left with 0 sub-paths and we can call it a failure logging all the permutations of the path
    //
    // Say if we have `./pictures/anything/some_file.png`, we want the next iteration to be `./pictures/some_file.png`
    // where 'pictures' is the constant directory provided by the user
    let mut trials = Vec::new();
    loop {
        let path_ = format!("./{dir}/{}", path.trim_start_matches("/"));
        match exists_sync(&path_) {
            Ok(val) => {
                if val {
                    log(&format!("Paths traversed so far: {trials:?}"));
                    log(&format!("Path found: {path_}"));
                    path = path_;
                    break;
                }
            }
            Err(err) => {
                return console_error(&format!("Could not call `fs.existsSync` API: {:?}", err.as_string()));
            }
        };

        let mut parts = path.split('/').filter(|x| !x.is_empty()).collect::<Vec<&str>>();

        if !parts.is_empty() {
            trials.push(path_.clone());
            parts.remove(0);
        }

        if parts.is_empty() {
            log(&format!("Path(s) traversed and not found: {trials:?}"));
            response_set_status(res, 404);
            response_set_status_text(res, "404 Not Found");
            return response_set_body_end(res, format!("Cannot GET {trials:?}").as_bytes());
        }

        path = parts.join("/");
    }

    // return the default EncryptedImageData if the request is not a layer8 request
    if headers_map.is_empty() || !headers_map.contains_key("x-tunnel") {
        return return_encrypted_image(res);
    }

    let data = {
        let buff = match read_file(&path) {
            Ok(val) => val,
            Err(err) => {
                console_error(&format!("Could not read file: {err:?}"));
                response_set_status(res, 500);
                response_set_status_text(res, "Internal Server Error");
                return response_set_body_end(res, b"500 Internal Server Error");
            }
        };

        let array_buffer = match buff.obj.dyn_ref::<js_sys::Uint8Array>() {
            Some(val) => val,
            None => {
                response_set_status(res, 500);
                response_set_status_text(res, "Internal Server Error");
                return response_set_body_end(res, b"500 Internal Server Error");
            }
        };

        array_buffer.to_vec()
    };

    let mime_type = data.sniff_mime_type().unwrap_or("application/octet-stream");

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
            response_set_status(res, 500);
            response_set_status_text(res, "Internal Server Error");
            response_set_body_end(res, b"500 Internal Server Error");
            return;
        }
    };

    // sending the response
    response_set_status(res, js_res.status);
    response_set_status_text(res, &js_res.status_text);
    response_add_header(res, "Content-Type", "application/json");
    response_add_header(res, "mp-JWT", &mp_jwt);

    let data = serde_json::to_string(&layer8_primitives::types::RoundtripEnvelope {
        data: base64_enc_dec.encode(&encrypted),
    })
    .expect("RoundtripEnvelope serializes to json");

    response_set_body_end(res, data.as_bytes());
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
                js_sys::Reflect::set(
                    &form_data,
                    &JsValue::from_str(k),
                    &JsValue::from_f64(x.parse::<f64>().expect_throw("expected the value to be a valid number; qed")),
                )
                .expect("expected form_data to be a mutable object");
            }
            x if x.eq("Boolean") => {
                js_sys::Reflect::set(
                    &form_data,
                    &JsValue::from_str(k),
                    &JsValue::from_bool(x.parse::<bool>().expect_throw("expected the value to be a valid boolean; qed")),
                )
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

fn prepare_data(res: &JsValue, data: &[u8], sym_key: &Jwk, jwt: &str) -> Response {
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

#[allow(non_snake_case)]
#[wasm_bindgen(js_name = TestWASM)]
pub fn test_wasm() -> JsValue {
    JsValue::from_str("42")
}

#[cfg(test)]
mod tests {
    use js_sys::Object;
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::*;

    #[allow(dead_code)]
    #[wasm_bindgen_test]
    fn test_wasm() {
        assert_eq!(super::test_wasm(), "42");
    }

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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
