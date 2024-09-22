use layer8_interceptor_rs::{crypto::Jwk, types::Response};

use crate::js_wrapper::{JsWrapper, Value};

pub fn prepare_data(res: &Value, data: &Value, sym_key: &Jwk, jwt: String) -> Response {
    let mut js_response = Response {
        body: serde_json::to_vec(data.get_value())
            .expect("we implemented Serialize for JsWrapper; qed"),
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
                            headers.push((
                                k.clone(),
                                val.to_string().expect("this field expected a string"),
                            ));
                        }

                        js_response.headers = headers
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
        .symmetric_encrypt(
            &serde_json::to_vec(&js_response).expect("the type implements Serialize"),
        )
        .expect("no internal errors expected on encryption");

    return Response {
        body,
        status: js_response.status,
        status_text: js_response.status_text,
        headers: vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("mp-JWT".to_string(), jwt),
        ],
    };
}
