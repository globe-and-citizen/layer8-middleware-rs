//! This is the API interface for the layer8 forward proxy.

use core::default::Default;
use std::{
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use base64::{self, engine::general_purpose::URL_SAFE as base64_enc_dec, Engine as _};
use bytes::Bytes;
use http::{
    header::{CONTENT_LENGTH, CONTENT_TYPE, HOST, TRANSFER_ENCODING},
    HeaderName, Method, Uri,
};
use log::{debug, error, info, warn};
use pingora::http::{RequestHeader, ResponseHeader};
use pingora_core::{
    prelude::{HttpPeer, Opt, Result},
    server::Server,
};
use pingora_proxy::{ProxyHttp, Session};
use serde_json::json;

mod middleware;
mod state;
mod websocket_ext;
use layer8_middleware_rs::{Ecdh, InMemStorage, InitEcdhReturn};
use layer8_primitives::{
    crypto::{base64_to_jwk, generate_key_pair, KeyUse},
    types::{self, Layer8Envelope, Request, RequestMetadata, RoundtripEnvelope, WebSocketPayload},
};
use state::{ConnectionContext, Responses};
use websocket_ext::{construct_raw_websocket_frame, parse_payload_from_raw_frame_bytes};

/// This is the reverse proxy instance for the layer8 middleware.
struct Layer8Proxy {
    service_port: u16,
    http_storage: Arc<Mutex<InMemStorage>>,
}

// UPSTREAM -> service_provider
// DOWNSTREAM -> FE

#[async_trait]
impl ProxyHttp for Layer8Proxy {
    type CTX = ConnectionContext;

    fn new_ctx(&self) -> Self::CTX {
        let (private_key, public_key) = generate_key_pair(KeyUse::Ecdh).expect("expected this call to be infallible");
        ConnectionContext {
            persistent_storage: InMemStorage {
                ecdh: Ecdh { private_key, public_key },
                ..Default::default()
            },
            ..Default::default()
        }
    }

    // This hook is responsible for processing the request metadata if provided
    async fn upstream_request_filter(&self, session: &mut Session, request_headers: &mut RequestHeader, ctx: &mut Self::CTX) -> Result<()> {
        debug!("-----------------------------------------------------------");
        debug!("---------------- CallStack: upstream_request_filter ----------------");
        debug!("-----------------------------------------------------------");
        debug!("Upstream Request Headers: {:?}", request_headers);
        debug!("-----------------------------------------------------------");

        // if is a duplex connection, ignore
        if session.is_upgrade_req() {
            return Ok(());
        }

        // persisting important headers used to identify and encrypt the client data
        {
            match request_headers.headers.get("x-client-uuid") {
                Some(val) => ctx.metadata.client_uuid = val.to_str().map_err(|e| to_pingora_err(&e.to_string()))?.to_string(),
                None => return Ok(()),
            }

            match request_headers.headers.get("x-tunnel") {
                Some(val) => {
                    ctx.metadata.x_tunnel = val
                        .to_str()
                        .map_err(|e| to_pingora_err(&e.to_string()))?
                        .parse::<bool>()
                        .map_err(|e| to_pingora_err(&e.to_string()))?
                }
                None => ctx.metadata.x_tunnel = false,
            }

            match request_headers.headers.get("x-ecdh-init") {
                Some(val) => ctx.metadata.x_ecdh_init = val.to_str().map_err(|e| to_pingora_err(&e.to_string()))?.to_string(),
                None => ctx.metadata.x_ecdh_init = String::new(),
            }

            match request_headers.headers.get("mp-jwt") {
                Some(val) => ctx.metadata.mp_jwt = val.to_str().map_err(|e| to_pingora_err(&e.to_string()))?.to_string(),
                None => ctx.metadata.mp_jwt = String::new(),
            }
        }

        // if it's not part of the tunnel, ignore
        if !ctx.metadata.x_tunnel {
            return Ok(());
        }

        // we have the headers we need, clear all else except for `layer8-request-header`
        let layer8_request_header = request_headers
            .headers
            .iter()
            .find(|(key, _)| key.eq(&HeaderName::from_str("layer8-request-header").unwrap()))
            .map(|v| v.1.clone());

        // we can only remove the headers iteratively
        for (key, _) in request_headers.headers.clone().iter() {
            if key.eq(&HOST) || key.eq("layer8-empty-body") {
                continue;
            }

            request_headers.remove_header(key);
        }

        if let Some(val) = layer8_request_header {
            let header_val = base64_enc_dec
                .decode(val.to_str().map_err(|e| to_pingora_err(&e.to_string()))?)
                .map_err(|e| to_pingora_err(&e.to_string()))?;

            let storage = Arc::clone(&self.http_storage);
            let keys = storage.lock().unwrap().keys.clone();
            let shared_secret = keys.get(&ctx.metadata.client_uuid).ok_or_else(|| {
                error!("Failed to find shared secret for client uuid: {}", ctx.metadata.client_uuid);
                to_pingora_err("Failed to find shared secret for client uuid")
            })?;

            let request_metadata =
                serde_json::from_slice::<RequestMetadata>(&shared_secret.symmetric_decrypt(&header_val).map_err(|e| to_pingora_err(&e.to_string()))?)
                    .map_err(|e| to_pingora_err(&e.to_string()))?;

            // overwrite the request header
            let path = {
                let url_path = Uri::from_str(&request_metadata.url_path.clone().unwrap_or("/".to_string())).map_err(|e| {
                    error!("Failed to parse url path: {}", e);
                    to_pingora_err(&e.to_string())
                })?;

                Uri::from_str(url_path.path_and_query().map(|v| v.as_str()).unwrap_or("/")).map_err(|e| {
                    error!("Failed to parse url path with query: {}", e);
                    to_pingora_err(&e.to_string())
                })?
            };

            let method = Method::from_bytes(request_metadata.method.as_bytes()).map_err(|e| to_pingora_err(&e.to_string()))?;

            request_headers.set_method(method);
            request_headers.set_uri(path);
            for (key, value) in request_metadata.headers {
                request_headers.insert_header(key, value.trim().to_lowercase()).map_err(|e| {
                    error!("Failed to append header: {}", e);
                    to_pingora_err(&e.to_string())
                })?;
            }

            // if we're requesting for assets like a logo, ok to skip the transfer encoding since the
            // body is empty
            if request_headers.remove_header("layer8-empty-body").is_none() {
                request_headers.insert_header(&TRANSFER_ENCODING, "chunked")?;
            }
        }

        Ok(())
    }

    // This hook is responsible for processing the request body and modifying it before we send it to the server.
    async fn request_body_filter(&self, session: &mut Session, body: &mut Option<Bytes>, end_of_stream: bool, ctx: &mut Self::CTX) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        debug!("----------------------------------------------------------------");
        debug!("---------------- CallStack: request_body_filter ----------------");
        debug!("----------------------------------------------------------------");

        if session.is_upgrade_req() {
            let data = match body {
                Some(val) => val,
                None => {
                    info!("body is empty");
                    return Ok(());
                }
            };

            ctx.payload_buff = parse_payload_from_raw_frame_bytes(data).map_err(|e| to_pingora_err(&e))?;
            match self.ecdh_exchange(ctx, session).await? {
                // tunnel is being set up, clear the body
                (Some(val), None) => {
                    ctx.responses = Responses::Init(val);

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
        }

        if ctx.metadata.client_uuid.is_empty() {
            return Ok(());
        }

        if let Some(body) = body {
            ctx.payload_buff.extend_from_slice(&body[..]);
            body.clear();
        }

        // we're ony interested in the whole request body
        if !end_of_stream {
            return Ok(());
        }

        match self.ecdh_exchange(ctx, session).await? {
            // tunnel is being set up, clear the body
            (Some(val), None) => ctx.responses = Responses::Init(val),

            // tunnel already setup; we only need to propagate the intended request body
            (None, Some(payload)) => _ = body.replace(Bytes::from(payload)),

            _ => return Err(to_pingora_err("Error processing data; we only expected the payload")),
        }

        ctx.payload_buff.clear();
        Ok(())
    }

    async fn response_filter(&self, session: &mut Session, upstream_response: &mut ResponseHeader, ctx: &mut Self::CTX) -> Result<()> {
        debug!("-----------------------------------------------------------");
        debug!("---------------- CallStack: response_filter ----------------");
        debug!("-----------------------------------------------------------");

        if session.is_upgrade_req() || ctx.metadata.client_uuid.is_empty() {
            return Ok(());
        }

        use state::Responses::*;
        let resp = match &ctx.responses {
            Init(val) => {
                let mut header = ResponseHeader::build(200, Option::None)?;
                header.append_header(&CONTENT_LENGTH, val.server_public_key.len())?;
                header.append_header("server_pubKeyECDH", val.server_public_key.clone())?;
                header.append_header("mp-jwt", val.mp_jwt.clone())?;
                *upstream_response = header;
                return Ok(());
            }

            // expect None, Some(_) will never be the case here
            _ => types::Response {
                status: upstream_response.status.as_u16(),
                status_text: upstream_response.status.as_str().to_string(),
                headers: upstream_response
                    .headers
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_string()))
                    .collect(),
                body: Vec::new(),
            },
        };

        let mut header = ResponseHeader::build(200, Option::None)?;
        header.insert_header(&CONTENT_TYPE, "application/json")?;
        header.insert_header(&TRANSFER_ENCODING, "chunked")?;
        *upstream_response = header;
        ctx.responses = Response(resp);
        Ok(())
    }

    fn response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>>
    where
        Self::CTX: Send + Sync,
    {
        debug!("-----------------------------------------------------------------");
        debug!("---------------- CallStack: response_body_filter ----------------");
        debug!("-----------------------------------------------------------------");

        use state::Responses::*;
        if session.is_upgrade_req() {
            if let Init(val) = &ctx.responses {
                let data = Layer8Envelope::WebSocket(WebSocketPayload {
                    payload: Option::None,
                    metadata: json!({
                        "mp-jwt": val.mp_jwt,
                        "server_pubKeyECDH":val.server_public_key,
                    }),
                })
                .to_json_bytes();

                let output = construct_raw_websocket_frame(&data, false).map_err(|e| to_pingora_err(&e))?;
                *body = Some(Bytes::from(output));
                ctx.payload_buff.clear();
                ctx.responses = None;
                return Ok(Option::None);
            }

            if let Some(raw) = body {
                let data = parse_payload_from_raw_frame_bytes(raw).map_err(|e| to_pingora_err(&e))?;

                debug!("---------------------------------------------------------------");
                debug!("Parsed Outgoing Data: {:?}", String::from_utf8_lossy(&data));
                debug!("---------------------------------------------------------------");

                let shared_secret = ctx.persistent_storage.keys.0.values().collect::<Vec<_>>()[0]; // FIXME: this is a hack revisit
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

            return Ok(Option::None);
        }

        if ctx.metadata.client_uuid.is_empty() {
            return Ok(Option::None);
        }

        // buffer the data
        if let Some(b) = body {
            ctx.payload_buff.extend_from_slice(&b[..]);
            b.clear();
        }

        if !end_of_stream {
            // we're still not at the last chunk, can't process the data yet
            return Ok(Option::None);
        }

        if let Response(val) = &mut ctx.responses {
            val.body.extend_from_slice(&ctx.payload_buff[..]);
            ctx.payload_buff.clear();
        }

        debug!("---------------------------------------------------------------");
        debug!("Response Body: {:?}", ctx.responses);
        debug!("---------------------------------------------------------------");

        match &ctx.responses {
            Init(val) => *body = Some(Bytes::from(val.server_public_key.as_bytes().to_vec())),

            Response(val) => {
                let in_mem_storage = Arc::clone(&self.http_storage);
                let storage = in_mem_storage.lock().unwrap();
                let shared_secret = storage.keys.get(&ctx.metadata.client_uuid).ok_or_else(|| {
                    error!("Failed to find shared secret for client uuid: {}", ctx.metadata.client_uuid);
                    to_pingora_err("Failed to find shared secret for client uuid")
                })?;

                let roundtrip = RoundtripEnvelope::encode(
                    &shared_secret
                        .symmetric_encrypt(&serde_json::to_vec(val).map_err(|e| to_pingora_err(&format!("Failed to serialize request: {}", e)))?)
                        .map_err(|e| to_pingora_err(&format!("Failed to encrypt request: {}", e)))?,
                );

                let resp = Layer8Envelope::Http(roundtrip).to_json_bytes();

                *body = Some(Bytes::from(resp));
            }

            _ => {}
        }

        ctx.responses = None;
        Ok(Option::None)
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

    let storage = {
        let (private_key, public_key) = generate_key_pair(KeyUse::Ecdh).expect("expected this call to be infallible");
        InMemStorage {
            ecdh: Ecdh { private_key, public_key },
            ..Default::default()
        }
    };

    let mut middleware = pingora_proxy::http_proxy_service(
        &server.configuration,
        Layer8Proxy {
            service_port,
            http_storage: Arc::new(Mutex::new(storage)),
        },
    );
    middleware.add_tcp(&format!("0.0.0.0:{}", port));
    server.add_service(middleware);
    server.run_forever()
}

impl Layer8Proxy {
    // if (Some(val), None) =>  the data from the client is for the the init tunnel handshake
    // (None, Some(val)) => the data from the client is from a subsequent call after the tunnel had been established
    async fn ecdh_exchange(&self, ctx: &mut ConnectionContext, session: &mut Session) -> Result<(Option<InitEcdhReturn>, Option<Vec<u8>>)> {
        let body = &ctx.payload_buff;
        let (metadata, envelope) = match body.is_empty() {
            false => {
                let envelope = Layer8Envelope::from_json_bytes(body).map_err(|e| {
                    error!("Failed to decode response: {e}, Data is :{}", String::from_utf8_lossy(body));
                    to_pingora_err(&e.to_string())
                })?;

                match envelope {
                    Layer8Envelope::WebSocket(payload) => {
                        warn!("-------------------------------------------------");
                        warn!("WebSocket Payload: {:?}", payload);
                        warn!("-------------------------------------------------");

                        let metadata = serde_json::from_value::<serde_json::Map<String, serde_json::Value>>(payload.metadata.clone())
                            .expect("we expect a json object as the metadata");
                        (metadata, Some(payload))
                    }

                    Layer8Envelope::Http(roundtrip) => {
                        let storage = Arc::clone(&self.http_storage);
                        let keys = storage.lock().unwrap().keys.clone();
                        let response_data = roundtrip
                            .decode()
                            .map_err(|e| to_pingora_err(&format!("Failed to decode response: {}", e)))?;

                        let shared_secret = keys.get(&ctx.metadata.client_uuid).ok_or_else(|| {
                            error!("Failed to find shared secret for client uuid: {}", ctx.metadata.client_uuid);
                            to_pingora_err("Failed to find shared secret for client uuid")
                        })?;

                        let payload = shared_secret
                            .symmetric_decrypt(&response_data)
                            .map_err(|e| to_pingora_err(&format!("Failed to decrypt response: {}", e)))?;

                        // we expect the payload to be a json object of type Request
                        let resp =
                            serde_json::from_slice::<Request>(&payload).map_err(|e| to_pingora_err(&format!("Failed to decode response: {}", e)))?;

                        return Ok((None, Some(resp.body)));
                    }
                }
            }

            true => {
                if session.is_upgrade_req() {
                    return Err(to_pingora_err("we don't expect a websocket request to get here; report this as a bug"));
                }

                // we expect the metadata to be in the headers, so no need to decode the body
                let mut map = serde_json::Map::new();

                if !ctx.metadata.x_ecdh_init.is_empty() {
                    map.insert("x-ecdh-init".to_string(), ctx.metadata.x_ecdh_init.clone().into());
                }

                if !ctx.metadata.client_uuid.is_empty() {
                    map.insert("x-client-uuid".to_string(), ctx.metadata.client_uuid.clone().into());
                }

                if !ctx.metadata.mp_jwt.is_empty() {
                    map.insert("mp-jwt".to_string(), ctx.metadata.mp_jwt.clone().into());
                }

                (map, None)
            }
        };

        let x_client_uuid = metadata.get("x-client-uuid").and_then(|x| x.as_str());

        // if we have the x-ecdh-init, this is the first time we are setting up the tunnel
        if let Some(x_ecdh_init) = metadata.get("x-ecdh-init").and_then(|x| x.as_str()) {
            let mp_jwt = metadata.get("mp-jwt").and_then(|y| y.as_str());
            let (x_client_uuid, mp_jwt) = match (x_client_uuid, mp_jwt) {
                (Some(x), Some(y)) => (x, y),
                _ => {
                    return Err(to_pingora_err("expected x-client-uuid, and mp-jwt in the metadata"));
                }
            };

            let val = match session.is_upgrade_req() {
                true => init_ecdh_tunnel(&mut ctx.persistent_storage, x_ecdh_init, x_client_uuid, mp_jwt).map(|val| (Some(val), None::<Vec<u8>>)),
                false => {
                    let storage = Arc::clone(&self.http_storage);
                    let mut storage = storage.lock().unwrap();
                    init_ecdh_tunnel(&mut storage, x_ecdh_init, x_client_uuid, mp_jwt).map(|val| (Some(val), None::<Vec<u8>>))
                }
            };

            return val;
        }

        let client_uuid = x_client_uuid.expect("expected x-client-uuid to be present; report this as a bug");

        // at this point we retrieve our keys and decrypt the data in the payload section
        match envelope {
            Some(ws_data) => {
                if ws_data.payload.is_none() {
                    return Err(to_pingora_err("expected a payload in the websocket envelope"));
                }

                let payload = ctx
                    .persistent_storage
                    .keys
                    .get(client_uuid)
                    .ok_or_else(|| {
                        error!("Failed to find shared secret for client uuid: {}", client_uuid);
                        to_pingora_err("Failed to find shared secret for client uuid")
                    })?
                    .symmetric_decrypt(
                        &base64_enc_dec
                            .decode(ws_data.payload.expect("expected the payload to be present"))
                            .map_err(|e| to_pingora_err(&e.to_string()))?,
                    )
                    .map_err(|e| to_pingora_err(&e))?;

                Ok((None, Some(payload)))
            }

            None => Err(to_pingora_err("expected a websocket envelope; report this as a bug")),
        }
    }
}

fn init_ecdh_tunnel(storage: &mut InMemStorage, x_ecdh_init: &str, x_client_uuid: &str, mp_jwt: &str) -> Result<InitEcdhReturn> {
    let user_pub_jwk = base64_to_jwk(x_ecdh_init).map_err(|e| to_pingora_err(&format!("failure to decode userPubJwk: {e}")))?;
    let shared_secret = storage
        .ecdh
        .get_private_key()
        .get_ecdh_shared_secret(&user_pub_jwk)
        .map_err(|e| to_pingora_err(&e))?;

    // adding the shared secret to the keys
    storage.keys.add(x_client_uuid, shared_secret.clone());

    let b64_shared_secret = shared_secret.export_as_base64();
    let b64_pub_key = storage.ecdh.get_public_key().export_as_base64();

    // saving the mp-jwt to the jwts
    storage.jwts.add(x_client_uuid, mp_jwt);

    Ok(InitEcdhReturn {
        shared_secret: b64_shared_secret,
        server_public_key: b64_pub_key,
        mp_jwt: mp_jwt.to_string(),
    })
}

pub(crate) fn to_pingora_err(val: &str) -> Box<pingora_core::Error> {
    debug!("to_pingora_err: {}", val);
    pingora_core::Error::because(pingora_core::ErrorType::InternalError, "", val)
}

#[allow(dead_code)] // important for the cli to shutdown, todo
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
