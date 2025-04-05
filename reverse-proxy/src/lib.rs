//! This is the API interface for the layer8 forward proxy.
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

mod middleware;
mod websocket_ext;
use layer8_middleware_rs::{Ecdh, InMemStorage};
use layer8_primitives::crypto::{base64_to_jwk, generate_key_pair, KeyUse};
use layer8_primitives::types::{Layer8Envelope, WebSocketPayload};
use websocket_ext::{construct_raw_websocket_frame, parse_payload_from_raw_frame_bytes};

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

        if session.get_header("l8-stop-signal").is_some() {
            info!("Received stop signal from the client");
            send_signal(libc::SIGINT);
        }

        Ok(false)
    }

    async fn request_body_filter(&self, session: &mut Session, body: &mut Option<Bytes>, _: bool, ctx: &mut Self::CTX) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // we only need to process the body if it is an upgrade request, else this can be done in the request_filter
        debug!("---------------- CallStack: request_body_filter ----------------");

        let data = match body {
            Some(val) => val,
            None => {
                info!("body is empty");
                return Ok(());
            }
        };

        if session.is_upgrade_req() {
            let encoded_data = parse_payload_from_raw_frame_bytes(data).map_err(|e| to_pingora_err(&e))?;
            match ecdh_exchange(ctx, &encoded_data, None).await? {
                // tunnel is being set up, clear the body
                (Some(val), None) => {
                    ctx.init_ecdh_payload = Some(Bytes::from(val));

                    // this part is a hack but necessary to ensure the handshake is completed
                    *body = Some(Bytes::from(
                        construct_raw_websocket_frame(b"init_tunnel", true).map_err(|e| to_pingora_err(&e))?,
                    ));
                    debug!("Finished handshake with middleware, waiting for return trip");
                }

                // tunnel already setup; we only need to rewrite the response body
                (None, Some(val)) => {
                    let output = construct_raw_websocket_frame(&val, true).map_err(|e| to_pingora_err(&e))?;
                    *body = Some(Bytes::from(output));
                }

                _ => {
                    error!("Error processing data");
                    return Err(to_pingora_err("Error processing data"));
                }
            }
            return Ok(());
        };

        // make sure we even need this data decoded or skip the tunnel
        if session.get_header("x-tunnel").is_none() || session.get_header("x-client-uuid").is_none() {
            return Ok(());
        }

        match ecdh_exchange(ctx, &data, None).await? {
            // tunnel is being set up, clear the body
            (Some(val), None) => {
                todo!()
            }

            // tunnel already setup; we only need to rewrite the response body
            (None, Some(val)) => {
                todo!()
            }

            _ => {
                error!("Error processing data");
                return Err(to_pingora_err("Error processing data"));
            }
        }

        // let init_ecdh = |resp: &JsValue| {
        //     let res = INMEM_STORAGE_INSTANCE.with(|storage| {
        //         let mut inmem_storage = storage.take();
        //         let res = internals::init_ecdh::initialize_ecdh(
        //             Value {
        //                 r#type: js_wrapper::Type::Object,
        //                 constructor: "Object".to_string(),
        //                 value: JsWrapper::Object(headers_map.clone()),
        //             },
        //             &mut inmem_storage,
        //         );

        //         storage.replace(inmem_storage);
        //         res
        //     });

        //     match res {
        //         Ok(res) => {
        //             log("ECDH Successfully Completed!");
        //             response_set_status(resp, 200);
        //             response_set_status_text(resp, "ECDH Successfully Completed!");
        //             response_add_header(resp, "mp-JWT", &res.mp_jwt);
        //             response_add_header(resp, "server_pubKeyECDH", &res.server_public_key);
        //             response_set_body_end(resp, res.server_public_key.as_bytes());
        //         }
        //         Err(err) => {
        //             console_error(&err);
        //             response_set_status(resp, 500);
        //             response_set_status_text(resp, "Failure to initialize ECDH");
        //         }
        //     }
        // };

        // we assume we are receiving the whole body
        let data = Layer8Envelope::from_json_bytes(&data).map_err(|e| {
            error!("Failed to decode response: {e}, Data is :{}", String::from_utf8_lossy(data));
            to_pingora_err(&e.to_string())
        })?;

        let content_type = session
            .get_header("Content-Type")
            .map(|v| v.to_str().unwrap().to_lowercase().trim().to_string());

        // we must find the raw data in the body
        if session.get_header("x-static").is_some() {
            if let Layer8Envelope::Raw(data) = data {
                let mut val = Vec::new();
                base64_enc_dec
                    .decode_vec(&data, &mut val)
                    .map_err(|e| to_pingora_err(&format!("Failed to decode response: {e}")))?;
                *body = Some(Bytes::from(val));
                return Ok(());
            }

            error!("Expected body to be Layer8Envelope::Raw");
            return Err(to_pingora_err("Expected body to be Layer8Envelope::Raw"));
        }

        // all other data must be of type wrapped in application/json
        if session
            .get_header("Content-Type")
            .map(|v| v.to_str().unwrap().to_lowercase().trim().to_string())
            .eq(&Some("application/json".to_string()))
        {
            if let Layer8Envelope::Http(data) = data {
                *body = Some(Bytes::from(
                    data.decode().map_err(|e| to_pingora_err(&format!("Failed to decode response: {e}")))?,
                ));

                return Ok(());
            }

            error!("Expected body to be Layer8Envelope::Http");
            return Err(to_pingora_err("Expected body to be Layer8Envelope::Http"));
        }

        Ok(())
    }

    fn response_body_filter(&self, session: &mut Session, body: &mut Option<Bytes>, _: bool, ctx: &mut Self::CTX) -> Result<Option<Duration>>
    where
        Self::CTX: Send + Sync,
    {
        debug!("---------------- CallStack: response_body_filter ----------------");

        if session.is_upgrade_req() {
            if let Some(init_ecdh_return) = ctx.init_ecdh_payload.as_ref() {
                debug!("---------------------------------------------------------------");
                debug!("Sending ECDH Init Payload: {:?}", String::from_utf8_lossy(init_ecdh_return));
                debug!("---------------------------------------------------------------");

                let output = construct_raw_websocket_frame(init_ecdh_return, false).map_err(|e| to_pingora_err(&e))?;
                *body = Some(Bytes::from(output));
                ctx.init_ecdh_payload = None;
                return Ok(None);
            }

            if let Some(raw) = body {
                let data = parse_payload_from_raw_frame_bytes(raw).map_err(|e| to_pingora_err(&e))?;

                debug!("---------------------------------------------------------------");
                debug!("Parsed Outgoing Data: {:?}", String::from_utf8_lossy(&data));
                debug!("---------------------------------------------------------------");

                let shared_secret = ctx.persistent_data.keys.0.values().collect::<Vec<_>>()[0]; // FIXME: this is a hack revisit
                let request_data = {
                    let encrypted_data = shared_secret
                        .symmetric_encrypt(&data)
                        .map_err(|e| to_pingora_err(&format!("Failed to encrypt request: {e}")))?;
                    let mut val = String::new();
                    base64_enc_dec.encode_string(encrypted_data, &mut val);

                    let roundtrip: WebSocketPayload = WebSocketPayload {
                        payload: Some(val),
                        metadata: json!({}),
                    };

                    construct_raw_websocket_frame(
                        &serde_json::to_vec(&Layer8Envelope::WebSocket(roundtrip))
                            .expect("expected the envelope to be serializable to a valid json object; qed"),
                        false,
                    )
                    .map_err(|e| to_pingora_err(&e))?
                };

                *body = Some(Bytes::from(request_data));
            }

            return Ok(None);
        }

        let data = match body {
            Some(val) => Layer8Envelope::from_json_bytes(&val).map_err(|e| {
                error!("Failed to decode response: {e}, Data is :{}", String::from_utf8_lossy(val));
                to_pingora_err(&e.to_string())
            })?,
            None => {
                info!("body is empty");
                return Ok(None);
            }
        };

        let content_type = session
            .get_header("Content-Type")
            .map(|v| v.to_str().unwrap().to_lowercase().trim().to_string());

        match content_type {
            Some(x) if x.eq("application/json") => {}

            Some(x) if x.eq("multipart/form-data") => {}
            _ => {}
        }

        // if session.get_header("multipart/form-data").is_some()

        // we're dealing with statics and/or other encoding formats
        if session.get_header("X-Static").is_some() {
            if !matches!(data, Layer8Envelope::Raw(val) if val.len() > 0) {
                error!("Expected a static response");
                return Err(to_pingora_err("Expected a static response"));
            }

            if let Layer8Envelope::Raw(static_data) = data {}
        }

        // we expect the body to be raw or http data, rewrite the response body undecoded
        // match data {
        //     Layer8Envelope::Http(data) => {
        //         *body = Some(Bytes::from(
        //             data.decode().map_err(|e| to_pingora_err(&format!("Failed to decode response: {e}")))?,
        //         ));
        //     }

        //     Layer8Envelope::WebSocket(_) => return Err(to_pingora_err("did not expect a websocket envolope for this request")),
        // }

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

    let metadata = match &envelope {
        Layer8Envelope::WebSocket(payload) => serde_json::from_value::<serde_json::Map<String, serde_json::Value>>(payload.metadata.clone())
            .expect("we expect a json object as the metadata"),
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

        return init_ecdh_tunnel(ctx, None, x_ecdh_init, x_client_uuid, mp_jwt)
            .await
            .map(|val| (Some(val), None));
    }

    // at this point we retrieve our keys and decrypt the data in the payload section
    let payload = match envelope {
        Layer8Envelope::WebSocket(ws_data) => {
            if ws_data.payload.is_none() {
                return Err(to_pingora_err("expected a payload in the websocket envelope"));
            }

            let shared_secret = ctx.persistent_data.keys.0.values().collect::<Vec<_>>()[0]; // FIXME: this is a hack revisit
            shared_secret
                .symmetric_decrypt(
                    &base64_enc_dec
                        .decode(ws_data.payload.expect("expected the payload to be present"))
                        .map_err(|e| to_pingora_err(&e.to_string()))?,
                )
                .map_err(|e| to_pingora_err(&e))?
        }
        _ => {
            return Err(to_pingora_err("expected a websocket envelope"));
        }
    };

    Ok((None, Some(payload)))
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

fn send_signal(signal: libc::c_int) {
    use libc::{getpid, kill};

    unsafe {
        let pid = getpid();
        assert_eq!(
            kill(pid, signal),
            0,
            "kill(pid = {}, {}) failed with error: {}",
            pid,
            signal,
            std::io::Error::last_os_error(),
        );

        info!("Sent signal: {}", signal);
    }
}
