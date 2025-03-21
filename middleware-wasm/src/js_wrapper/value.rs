use std::collections::HashMap;

use js_sys::{Array, Object};
use serde::ser::{SerializeMap, SerializeSeq};
use wasm_bindgen::{JsValue, UnwrapThrowExt};

#[derive(Debug, PartialEq)]
pub enum Type {
    Number = 0,
    Boolean,
    String,
    Object,
    Array,
    Null,
    Undefined,
}

#[derive(Debug, PartialEq, Clone)]
pub enum JsWrapper {
    Number(f64),
    Boolean(bool),
    String(String),
    Object(HashMap<String, JsWrapper>),
    Array(Vec<JsWrapper>),
    Null,
    Undefined,
}

impl JsWrapper {
    pub fn get_type(&self) -> Type {
        match self {
            JsWrapper::Number(_) => Type::Number,
            JsWrapper::Boolean(_) => Type::Boolean,
            JsWrapper::String(_) => Type::String,
            JsWrapper::Object(_) => Type::Object,
            JsWrapper::Array(_) => Type::Array,
            JsWrapper::Null => Type::Null,
            JsWrapper::Undefined => Type::Undefined,
        }
    }

    pub fn js_value(&self) -> JsValue {
        match self {
            JsWrapper::Number(val) => JsValue::from_f64(*val),
            JsWrapper::Boolean(val) => JsValue::from_bool(*val),
            JsWrapper::String(val) => JsValue::from_str(val),
            JsWrapper::Object(val) => {
                let obj = Object::new();
                for (key, value) in val.iter() {
                    js_sys::Reflect::set(&obj, &JsValue::from_str(key), &value.js_value()).expect_throw("infalliable");
                }
                JsValue::from(obj)
            }
            JsWrapper::Array(val) => {
                let arr = Array::new();
                for value in val.iter() {
                    arr.push(&value.js_value());
                }
                JsValue::from(arr)
            }
            JsWrapper::Null => JsValue::null(),
            JsWrapper::Undefined => JsValue::undefined(),
        }
    }

    pub fn to_string(&self) -> Result<String, String> {
        match self {
            JsWrapper::String(val) => Ok(val.clone()),
            val => Err(format!("type {val:?} is not string")),
        }
    }

    pub fn to_number(&self) -> Result<f64, String> {
        match self {
            JsWrapper::Number(val) => Ok(*val),
            val => Err(format!("type {val:?} is not string")),
        }
    }
}

impl serde::Serialize for JsWrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            JsWrapper::Number(value) => serializer.serialize_f64(*value),
            JsWrapper::Boolean(value) => serializer.serialize_bool(*value),
            JsWrapper::String(value) => serializer.serialize_str(value),
            JsWrapper::Object(value) => {
                let mut map = serializer.serialize_map(Some(value.len()))?;
                for (key, val) in value.iter() {
                    map.serialize_entry(key, &val)?;
                }
                map.end()
            }
            JsWrapper::Array(value) => {
                let mut array = serializer.serialize_seq(Some(value.len()))?;
                for v in value.iter() {
                    array.serialize_element(v)?;
                }
                array.end()
            }
            JsWrapper::Null | JsWrapper::Undefined => serializer.serialize_none(),
        }
    }
}

#[derive(Debug)]
pub struct Value {
    pub r#type: Type,
    pub constructor: String,
    pub value: JsWrapper,
}

impl Value {
    pub fn get(&self, key: &str) -> Result<Option<&JsWrapper>, String> {
        if let JsWrapper::Object(map) = &self.value {
            return match map.get(key) {
                Some(value) => Ok(Some(value)),
                None => Ok(None),
            };
        }

        Err("Value is not an object".to_string())
    }

    pub fn set(&mut self, key: &str, value: JsWrapper) -> Result<(), String> {
        match &mut self.value {
            JsWrapper::Object(map) => {
                map.insert(key.to_string(), value);
                Ok(())
            }

            _ => Err("Value is not an object".to_string()),
        }
    }

    pub fn get_value(&self) -> &JsWrapper {
        &self.value
    }

    pub fn get_type(&self) -> &Type {
        &self.r#type
    }

    pub fn is_null(&self) -> bool {
        self.r#type.eq(&Type::Null)
    }

    pub fn is_undefined(&self) -> bool {
        self.r#type.eq(&Type::Undefined)
    }

    pub fn is_object(&self) -> bool {
        self.r#type.eq(&Type::Object)
    }

    pub fn is_string(&self) -> bool {
        self.r#type.eq(&Type::String)
    }
}

/// The only types on this conversion are:
/// - Number
/// - Boolean
/// - String
/// - Object
/// - Array
/// - Null
pub fn to_value_from_js_value(js_value: &JsValue) -> Result<Value, String> {
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
            if let Ok(val) = to_value_from_js_value(&elem) {
                vec.push(val.value);
            }
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
            if key_val_entry.length() != 2 {
                continue;
            }

            let key = key_val_entry.get(0).as_string().expect("expected key to be a string; qed");
            if let Ok(val) = to_value_from_js_value(&key_val_entry.get(1)) {
                map.insert(key, val.value);
            }
        }

        return Ok(Value {
            r#type: Type::Object,
            constructor: "Object".to_string(),
            value: JsWrapper::Object(map),
        });
    }

    if js_value.is_null() {
        return Ok(Value {
            r#type: Type::Null,
            constructor: "Null".to_string(),
            value: JsWrapper::Null,
        });
    }

    if js_value.is_undefined() {
        return Ok(Value {
            r#type: Type::Undefined,
            constructor: "Undefined".to_string(),
            value: JsWrapper::Undefined,
        });
    }

    Err("Unknown type".to_string())
}
