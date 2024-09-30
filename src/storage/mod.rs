use std::{cell::Cell, collections::HashMap};

use layer8_interceptor_rs::crypto::{generate_key_pair, Jwk, KeyUse};

// The module runs in the single threaded wasm environment, ok to use thread_local
thread_local! {
    pub static INMEM_STORAGE_INSTANCE: Cell<InMemStorage> = {
        let (private_key, public_key) = generate_key_pair( KeyUse::Ecdh).expect("expected this call to be infallible");
        Cell::new(InMemStorage {
            ecdh: Ecdh {
                private_key,
                public_key,
            },
            keys: Keys(vec![]),
            jwts: Jwts(vec![]),
        })
    };
}

#[derive(Debug, Clone, Default)]
pub struct Ecdh {
    pub private_key: Jwk,
    pub public_key: Jwk,
}

impl Ecdh {
    pub fn get_private_key(&self) -> &Jwk {
        &self.private_key
    }

    pub fn get_public_key(&self) -> &Jwk {
        &self.public_key
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Keys(pub Vec<HashMap<String, Jwk>>);

impl Keys {
    pub fn add(&mut self, key: &str, value: Jwk) {
        self.0.append(&mut vec![HashMap::from([(key.to_string(), value)])]);
    }

    pub fn get(&self, key: &str) -> Option<&Jwk> {
        for map in self.0.iter() {
            if let Some(value) = map.get(key) {
                return Some(value);
            }
        }

        None
    }
}

#[derive(Debug, Clone, Default)]
pub struct Jwts(pub Vec<HashMap<String, String>>);

impl Jwts {
    // pub fn add(&mut self, key: &str, value: &str) {
    //     self.0.append(&mut vec![HashMap::from([(key.to_string(), value.to_string())])]);
    // }

    pub fn get(&self, key: &str) -> Option<&String> {
        for map in self.0.iter() {
            if let Some(value) = map.get(key) {
                return Some(value);
            }
        }

        None
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct InMemStorage {
    pub ecdh: Ecdh,
    pub keys: Keys,
    pub jwts: Jwts,
}
