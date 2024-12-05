use wasm_bindgen::prelude::*;

// This imports are necessary, there's some type erasure? working in the transformed Rust and/or APIs transformed that
// are not ported 1:1 from JS to Rust
use wasm_bindgen::JsValue;
#[wasm_bindgen(module = "/src/js_wrapper/js_utility_functions.js")]
extern "C" {
    pub fn array_fn(dest: JsValue) -> JsValue;
    pub fn single_fn(dest: JsValue) -> JsValue;
    pub fn as_json_string(val: &JsValue) -> String;

    pub fn request_set_header(req: &JsValue, key: &str, val: &str);
    pub fn request_set_body(req: &JsValue, body: JsValue);
    pub fn request_set_url(req: &JsValue, url: &str);
    pub fn request_get_url(req: &JsValue) -> String;
    pub fn request_set_method(req: &JsValue, method: &str);
    pub fn request_headers(req: &JsValue) -> JsValue;
    #[wasm_bindgen(catch)]
    pub fn request_get_body_string(req: &JsValue) -> Result<String, JsValue>;
    pub fn request_callbacks(res: &JsValue, symmetric_key: &str, mp_jwt: &str, respond_callback: JsValue);

    pub fn response_add_header(res: &JsValue, key: &str, val: &str);
    pub fn response_set_status(res: &JsValue, status: u16);
    pub fn response_set_status_text(res: &JsValue, status_text: &str);
    pub fn response_set_body(res: &JsValue, body: &[u8]);
    pub fn response_get_headers(res: &JsValue) -> JsValue;
    pub fn response_get_status(res: &JsValue) -> JsValue;
    pub fn response_get_status_text(res: &JsValue) -> JsValue;
    pub fn response_end(res: &JsValue, body: JsValue);

    pub fn get_url_path(js_str: &str) -> JsValue;
}
