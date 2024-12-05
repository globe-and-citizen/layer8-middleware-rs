use wasm_bindgen::prelude::*;

/// This is a wrapper for the `AssetsFunctions` object in JS.
/// This is necessary to preserve type information for the generated JS API.
#[wasm_bindgen(getter_with_clone)]
pub struct AssetsFunctionsWrapper {
    pub single: js_sys::Function,
    pub array: js_sys::Function,
}
