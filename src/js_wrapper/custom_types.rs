use wasm_bindgen::prelude::*;

/// This is a wrapper for the `AssetsFunctions` object in JS.
/// This is necessary to preserve type information for the generated JS API.
#[wasm_bindgen(getter_with_clone)]
pub struct AssetsFunctionsWrapper {
    /// This function is used to upload a file to the server.
    ///   * @param {string} file_name: The name of the property in the request body object that contains the file name.
    ///  * @returns {(req: any, res: any, next?: () => void) => void}: The next argument is optional and will be called if provided.
    pub single: js_sys::Function,

    /// This function is used to upload a files to the server.
    ///  * @param {string} file_collection_name: The name of the property in the request body object that contains the array of file names.
    /// * @returns {(req: any, res: any, next?: () => void) => void}: The next argument is optional and will be called if provided.
    pub array: js_sys::Function,
}
