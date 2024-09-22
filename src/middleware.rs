use js_sys::Object;
use wasm_bindgen::prelude::*;

use crate::js_wrapper;

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
    // [[key, value],...]  2d array
    let req_object = {
        let val = Object::try_from(&req).expect("expected the req to be an object; qed");
        Object::entries(val)
    };

    let mut done_on_headers = false;
    for entry in req_object.iter() {
        if entry.is_null() || entry.is_undefined() {
            // we skip null or undefined entries if any
            continue;
        }
    }

    if !done_on_headers {
        console_error("Headers not found in request object");
        return JsValue::NULL;
    }

    let req_object: js_wrapper::Value = req
        .try_into()
        .expect("we expect this req object to be parsable");

    todo!()
}

#[cfg(test)]
mod tests {
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_wasm() {
        assert_eq!(super::test_wasm(), "42");
    }

    // #[wasm_bindgen_test]
    // fn test_middleware() {
    //     let req = js_sys::Object::new();
    //     let resp = js_sys::Object::new();
    //     let next = js_sys::Object::new();

    //     assert_eq!(super::wasm_middleware(req, resp, next), JsValue::NULL);
    // }
}
