//! This is the API interface for the layer8 forward proxy.

use std::io::{Cursor, Read};
use std::time::Duration;

use async_trait::async_trait;
use base64::{self, engine::general_purpose::URL_SAFE as base64_enc_dec, Engine as _};
use bytes::Bytes;
use log::{debug, error, info};
use pingora_core::prelude::Opt;
use pingora_core::server::Server;
use pingora_core::{prelude::HttpPeer, Result};
use pingora_proxy::{ProxyHttp, Session};
use serde_json::json;

use layer8_middleware_rs::{Ecdh, InMemStorage};
use layer8_primitives::crypto::{base64_to_jwk, generate_key_pair, KeyUse};
use layer8_primitives::types::{Layer8Envelope, WebSocketPayload};
use layer8_tungstenite::protocol::frame::{coding::Data, Frame, FrameHeader};

struct Layer8Proxy {
    service_port: u16,
}

struct Context {
    persistent_data: InMemStorage,
    init_ecdh_payload: Option<Bytes>,
}

#[async_trait]
impl ProxyHttp for Layer8Proxy {
    type CTX = Context;

    fn new_ctx(&self) -> Self::CTX {
        let (private_key, public_key) = generate_key_pair(KeyUse::Ecdh).expect("expected this call to be infallible");
        Context {
            persistent_data: InMemStorage {
                ecdh: Ecdh { private_key, public_key },
                ..Default::default()
            },
            init_ecdh_payload: None,
        }
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        debug!("---------------- CallStack: request_filter ----------------");
        if session.is_upgrade_req() {
            return Ok(false);
        }

        Ok(false)
    }

    async fn request_body_filter(&self, session: &mut Session, body: &mut Option<Bytes>, _: bool, ctx: &mut Self::CTX) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // we only need to process the body if it is an upgrade request, else this can be done in the request_filter
        debug!("---------------- CallStack: request_body_filter ----------------");
        if !session.is_upgrade_req() {
            return Ok(());
        };

        let data = match body {
            Some(val) => val,
            None => {
                info!("body is empty");
                return Ok(());
            }
        };

        let data_placeholder = {
            let mut raw = Cursor::new(data);
            let (header, _) = FrameHeader::parse(&mut raw).unwrap().unwrap();
            let mut payload = Vec::new();
            raw.read_to_end(&mut payload).unwrap();
            let frame = Frame::from_payload(header, payload.into());
            frame.into_payload()
        };

        match ecdh_exchange(ctx, &data_placeholder, None).await? {
            // tunnel is being set up, clear the body
            (Some(val), None) => {
                let output = {
                    let frame = Frame::message(
                        b"init_tunnel".to_vec(),
                        layer8_tungstenite::protocol::frame::coding::OpCode::Data(Data::Text),
                        false,
                    );

                    let mut output = Vec::with_capacity(frame.len());
                    frame
                        .format(&mut output)
                        .map_err(|e| to_pingora_err(&format!("error constructing frame data: {e}")))?;

                    output
                };

                ctx.init_ecdh_payload = Some(Bytes::from(val));
                *body = Some(Bytes::from(output));
                debug!("Finished handshake with middleware, waiting for return trip");
            }

            // tunnel already setup; we only need to rewrite the response body
            (None, Some(val)) => {
                let frame = Frame::message(val, layer8_tungstenite::protocol::frame::coding::OpCode::Data(Data::Text), false);
                let mut output = Vec::with_capacity(frame.len());
                frame
                    .format(&mut output)
                    .map_err(|e| to_pingora_err(&format!("error constructing frame data: {e}")))?;
                *body = Some(Bytes::from(output));
            }

            _ => {
                error!("Error processing data");
                return Err(to_pingora_err("Error processing data"));
            }
        }

        return Ok(());
    }

    fn response_body_filter(&self, session: &mut Session, body: &mut Option<Bytes>, _: bool, ctx: &mut Self::CTX) -> Result<Option<Duration>>
    where
        Self::CTX: Send + Sync,
    {
        debug!("---------------- CallStack: response_body_filter ----------------");
        if !session.is_upgrade_req() {
            return Ok(None);
        }

        if let Some(init_ecdh_return) = ctx.init_ecdh_payload.clone() {
            let output = {
                let frame = Frame::message(
                    init_ecdh_return,
                    layer8_tungstenite::protocol::frame::coding::OpCode::Data(Data::Text),
                    false,
                );
                let mut output = Vec::with_capacity(frame.len());
                frame
                    .format(&mut output)
                    .map_err(|e| to_pingora_err(&format!("error constructing frame data: {e}")))?;

                output
            };

            *body = Some(Bytes::from(output));
            ctx.init_ecdh_payload = None;
            return Ok(None);
        }

        if let Some(raw) = body {
            let data = {
                let mut raw = Cursor::new(raw);
                let (header, _) = FrameHeader::parse(&mut raw).unwrap().unwrap();
                let mut payload = Vec::new();
                raw.read_to_end(&mut payload).unwrap();
                let frame = Frame::from_payload(header, payload.into());
                frame.into_payload()
            };

            let shared_secret = ctx.persistent_data.keys.0.iter().map(|(_, v)| v).collect::<Vec<_>>()[0]; // this is a hack revisit
            let request_data = {
                let encrypt_data = shared_secret
                    .symmetric_encrypt(&data)
                    .map_err(|e| to_pingora_err(&format!("Failed to encrypt request: {e}")))?;

                let mut val = String::new();
                base64_enc_dec.encode_string(encrypt_data, &mut val);

                let roundtrip = WebSocketPayload {
                    payload: Some(val),
                    metadata: json!({}),
                };

                let frame = Frame::message(
                    serde_json::to_vec(&roundtrip).expect("expected the roundtrip to be serializable to a valid json object; qed"),
                    layer8_tungstenite::protocol::frame::coding::OpCode::Data(Data::Text),
                    false,
                );
                let mut output = Vec::with_capacity(frame.len());
                frame
                    .format(&mut output)
                    .map_err(|e| to_pingora_err(&format!("error constructing frame data: {e}")))?;

                output
            };

            *body = Some(Bytes::from(request_data));
        }

        Ok(None)
    }

    // determines only the upstream peer
    async fn upstream_peer(&self, _: &mut Session, _: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        debug!(
            "upstream_peer: service_port: {}, service_host: one.one.one.one, service_tls: false",
            self.service_port
        );
        let peer = Box::new(HttpPeer::new(("localhost", self.service_port), false, "one.one.one.one".to_string()));
        Ok(peer)
    }
}

/// This is a blocking operation that runs the proxy server. The server is stopped when it encounters an error or interrupt signals.
pub fn run_proxy_server(port: u16, service_port: u16, daemonize: bool) {
    let mut server = Server::new(Opt {
        daemon: daemonize,
        ..Default::default()
    })
    .unwrap();

    let mut middleware = pingora_proxy::http_proxy_service(&server.configuration, Layer8Proxy { service_port });
    middleware.add_tcp(&format!("0.0.0.0:{}", port));
    server.add_service(middleware);
    server.run_forever()
}

// fixme: this function assumes the exchange is for webassembly data; I'll be improving this to be more generic after we have a working prototype
async fn ecdh_exchange(ctx: &mut Context, data: &[u8], _session: Option<&mut Session>) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
    let envelope = Layer8Envelope::from_json_bytes(data).map_err(|e| {
        error!("Failed to decode response: {e}, Data is :{}", String::from_utf8_lossy(data));
        to_pingora_err(&e.to_string())
    })?;

    let metadata = match envelope {
        Layer8Envelope::WebSocket(payload) => {
            serde_json::from_value::<serde_json::Map<String, serde_json::Value>>(payload.metadata).expect("we expect a json object as the metadata")
        }
        _ => {
            return Err(to_pingora_err("expected a websocket envelope"));
        }
    };

    // if we have the x-ecdh-init, this is the first time we are setting up the tunnel
    if let Some(x_ecdh_init) = metadata.get("x-ecdh-init").and_then(|x| x.as_str()) {
        let x_client_uuid = metadata.get("x-client-uuid").and_then(|x| x.as_str());
        let mp_jwt = metadata.get("mp-jwt").and_then(|y| y.as_str());
        let (x_client_uuid, mp_jwt) = match (x_client_uuid, mp_jwt) {
            (Some(x), Some(y)) => (x, y),
            _ => {
                return Err(to_pingora_err("expected x-client-uuid, and mp-jwt in the metadata"));
            }
        };

        return init_ecdh_tunnel(ctx, None, &x_ecdh_init, &x_client_uuid, &mp_jwt)
            .await
            .map(|val| (Some(val), None));
    }

    todo!()
}

async fn init_ecdh_tunnel(
    ctx: &mut Context,
    _session: Option<&mut Session>,
    x_ecdh_init: &str,
    x_client_uuid: &str,
    mp_jwt: &str,
) -> Result<Vec<u8>> {
    let user_pub_jwk = base64_to_jwk(x_ecdh_init).map_err(|e| to_pingora_err(&format!("failure to decode userPubJwk: {e}")))?;

    debug!("---------------------------------------------------------------");
    debug!("InMemStorage: {:?}", ctx.persistent_data);
    debug!("---------------------------------------------------------------");

    let shared_secret = ctx
        .persistent_data
        .ecdh
        .get_private_key()
        .get_ecdh_shared_secret(&user_pub_jwk)
        .map_err(|e| to_pingora_err(&e))?;

    // adding the shared secret to the keys
    ctx.persistent_data.keys.add(x_client_uuid, shared_secret.clone());
    let b64_pub_key = ctx.persistent_data.ecdh.get_public_key().export_as_base64();

    // saving the mp-jwt to the jwts
    ctx.persistent_data.jwts.add(x_client_uuid, mp_jwt);

    info!("ECDH Successfully Completed!");
    Ok(Layer8Envelope::WebSocket(WebSocketPayload {
        payload: None,
        metadata: json!({
            "mp-jwt": mp_jwt,
            "server_pubKeyECDH": b64_pub_key,
        }),
    })
    .to_json_bytes())
}

pub(crate) fn to_pingora_err(val: &str) -> Box<pingora_core::Error> {
    debug!("to_pingora_err: {}", val);
    pingora_core::Error::because(pingora_core::ErrorType::InternalError, "", val)
}
