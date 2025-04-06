use std::sync::{Arc, Mutex};

use bytes::Bytes;
use once_cell::sync::Lazy;

use layer8_middleware_rs::{Ecdh, InMemStorage};
use layer8_primitives::{
    crypto::{generate_key_pair, KeyUse},
    types::Response,
};

/// This is the in-memory storage for the reverse proxy for single roundtrip connections.
pub static HTTP_INMEM_STORAGE: Lazy<Arc<Mutex<InMemStorage>>> = Lazy::new(|| {
    let (private_key, public_key) = generate_key_pair(KeyUse::Ecdh).expect("expected this call to be infallible");
    Arc::new(Mutex::new(InMemStorage {
        ecdh: Ecdh { private_key, public_key },
        ..Default::default()
    }))
});

/// This context is used to store state across the lifetime of the connection.
pub struct ConnectionContext {
    /// This holds the state expected to be persisted across the lifetime of the connection.
    pub persistent_storage: InMemStorage,
    /// This holds data for the first payload sent to the service_provider, echoing it back after a successful
    /// connection.
    pub init_echo_payload: Option<Bytes>,

    pub roundtrip_response_cache: Response,
}
