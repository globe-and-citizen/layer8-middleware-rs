use std::fmt::Debug;

use layer8_middleware_rs::{InMemStorage, InitEcdhReturn};
use layer8_primitives::types;

/// This context is used to store state across the lifetime of the connection.
#[derive(Debug, Default)]
pub struct ConnectionContext {
    /// This holds the state expected to be persisted across the lifetime of the connection.
    pub persistent_storage: InMemStorage,
    /// This holds data that is propagated from one filter to another.
    pub payload_buff: Vec<u8>,
    pub metadata: Metadata,
    pub responses: Responses,
}

pub enum Responses {
    None,
    Init(InitEcdhReturn),
    Response(types::Response),
}

impl Default for Responses {
    fn default() -> Self {
        Responses::None
    }
}

impl std::fmt::Debug for Responses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Responses::None => write!(f, "Responses::None"),
            Responses::Init(val) => write!(f, "Responses::Init({:?})", val),
            Responses::Response(val) => write!(f, "Responses::Response({:?})", val),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Metadata {
    /// This is the UUID of the client that is connected to the proxy server before the header values are overwritten.
    pub client_uuid: String,
    /// This is the user's public jwk, which is used to encrypt the data that is sent to the client.
    pub x_ecdh_init: String,
    /// This is the header that identifies the request as part of the tunnel.
    pub x_tunnel: bool,
    pub mp_jwt: String,
}
