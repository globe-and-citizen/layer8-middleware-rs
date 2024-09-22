use std::collections::HashMap;

use js_sys::{Array, Object};
use serde::ser::{SerializeMap, SerializeSeq};
use wasm_bindgen::JsValue;

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

#[derive(Debug)]
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

pub struct Value {
    r#type: Type,
    constructor: String,
    value: JsWrapper,
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
}

/// The only types on this conversion are:
/// - Number
/// - Boolean
/// - String
/// - Object
/// - Array
/// - Null
impl TryInto<Value> for JsValue {
    type Error = String;
    fn try_into(self) -> Result<Value, Self::Error> {
        // Number
        if let Some(val) = self.as_f64() {
            return Ok(Value {
                r#type: Type::Number,
                constructor: "Number".to_string(),
                value: JsWrapper::Number(val),
            });
        }

        // Boolean
        if let Some(val) = self.as_bool() {
            return Ok(Value {
                r#type: Type::Boolean,
                constructor: "Boolean".to_string(),
                value: JsWrapper::Boolean(val),
            });
        }

        // String
        if self.is_string() {
            return Ok(Value {
                r#type: Type::String,
                constructor: "String".to_string(),
                value: JsWrapper::String(self.as_string().unwrap()),
            });
        }

        // Object
        if self.is_object() {
            // [[key, value],...]  2d array
            let req_object = {
                let val = Object::try_from(&self).expect("expected the req to be an object; qed");
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
                let key = key_val_entry
                    .get(0)
                    .as_string()
                    .expect("expected key to be a string; qed");
                let value: Value = key_val_entry.get(1).try_into()?;
                map.insert(key, value.value);
            }

            return Ok(Value {
                r#type: Type::Object,
                constructor: "Object".to_string(),
                value: JsWrapper::Object(map),
            });
        }

        // Array
        if self.is_array() {
            let arr = Array::from(&self);
            let mut vec = Vec::new();
            for elem in arr {
                let converted_elem: Value = elem.try_into()?;
                vec.push(converted_elem.value);
            }

            return Ok(Value {
                r#type: Type::Array,
                constructor: "Array".to_string(),
                value: JsWrapper::Array(vec),
            });
        }

        if self.is_null() {
            return Ok(Value {
                r#type: Type::Null,
                constructor: "Null".to_string(),
                value: JsWrapper::Null,
            });
        }

        if self.is_undefined() {
            return Ok(Value {
                r#type: Type::Undefined,
                constructor: "Undefined".to_string(),
                value: JsWrapper::Undefined,
            });
        }

        Err("Unknown type".to_string())
    }
}
