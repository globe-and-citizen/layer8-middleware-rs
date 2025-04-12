//! This is the API interface for the layer8 forward proxy.
use core::default::Default;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use base64::{self, engine::general_purpose::URL_SAFE as base64_enc_dec, Engine as _};
use bytes::Bytes;
use http::Method;
use log::{debug, error, info};
use pingora::{
    http::{RequestHeader, ResponseHeader},
    modules::http::HttpModules,
};
use pingora_core::{
    prelude::{HttpPeer, Opt, Result},
    server::Server,
};
use pingora_proxy::{ProxyHttp, Session};

mod http_filters;
mod memory;
mod middleware;
mod websocket_filters;
use layer8_middleware_rs::{Ecdh, InMemStorage, InitEcdhReturn};
use layer8_primitives::{
    crypto::{base64_to_jwk, generate_key_pair, KeyUse},
    types::{Layer8Envelope, Request, Response, WebSocketPayload},
};
use memory::ConnectionContext;
use serde_json::json;
use websocket_filters::{construct_raw_websocket_frame, parse_payload_from_raw_frame_bytes, WebsocketModule};

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
            payload_buff: Vec::new(),
        }
    }

    fn init_downstream_modules(&self, modules: &mut HttpModules) {
        modules.add_module(WebsocketModule::module());
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        debug!("-----------------------------------------------------------");
        debug!("---------------- CallStack: request_filter ----------------");
        debug!("-----------------------------------------------------------");

        if session.get_header("l8-stop-signal").is_some() {
            info!("Received stop signal from the client");
            send_signal(libc::SIGINT);
            return Ok(false);
        }

        // we don't process requests that are not part of the tunnel, or for duplex connections in this filter
        if session.is_upgrade_req() || (session.get_header("x-tunnel").is_none() && session.get_header("x-client-uuid").is_none()) {
            return Ok(false);
        }

        let mut body = Vec::new();
        loop {
            match session.read_request_body().await? {
                Some(data) => {
                    body.extend_from_slice(&data);
                }
                None => {
                    debug!("No data to read");
                    break;
                }
            }
        }

        let body = if body.is_empty() { None } else { Some(Bytes::from(body)) };
        match self.ecdh_exchange(ctx, &body, session).await? {
            // tunnel is being set up, clear the body
            (Some(val), None) => {
                // let's respond without even sending this to the server
                let mut header = ResponseHeader::build(200, None)?;
                header.append_header("Content-Length", val.server_public_key.len().to_string())?;
                session.write_response_header_ref(&header).await?;

                session
                    .write_response_body(Some(Bytes::from(val.server_public_key.as_bytes().to_vec())), true)
                    .await?;

                return Ok(true);
            }

            // tunnel already setup; we only need to propagate the intended request body to the request_body filter
            (None, Some(payload)) => ctx.payload_buff = payload,

            _ => {
                return Err(to_pingora_err("Error processing data"));
            }
        }

        Ok(false)
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
        debug!("---------------- CallStack: response_body_filter ----------------");

        if session.is_upgrade_req() {
            if let Some(init_echo_payload) = ctx.payload_buff.as_ref() {
                debug!("---------------------------------------------------------------");
                debug!("Sending ECDH Init Payload: {:?}", String::from_utf8_lossy(init_echo_payload));
                debug!("---------------------------------------------------------------");

                let output = construct_raw_websocket_frame(init_echo_payload, false).map_err(|e| to_pingora_err(&e))?;
                *body = Some(Bytes::from(output));
                ctx.payload_buff = None;
                return Ok(None);
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

            return Ok(None);
        }

        // buffer the data
        if let Some(b) = body {
            ctx.payload_buff.extend_from_slice(&b[..]);
            b.clear();
        }

        // we're still not at the last chunk, can't process the data yet
        if !end_of_stream {
            return Ok(None);
        }

        // for now lets assume application/json
        {
            // encoding headers written to the response object
            let mut resp = Response::default();

            if let Some(written_response_headers) = session.response_written() {
                resp.status = written_response_headers.status.as_u16();

                for (header_name, header_value) in &written_response_headers.headers {
                    resp.headers
                        .push((header_name.as_str().to_string(), header_value.clone().to_str().unwrap().to_string()));
                }
            }

            // write response header
            let mut response_header = ResponseHeader::build(200, None)?;
            response_header.append_header("content-type", "application/json")?;

            // session.write_response_header(Box::new(response_header), false).await;xxx
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
    async fn ecdh_exchange(
        &self,
        ctx: &mut ConnectionContext,
        body: &Option<Bytes>,
        session: &mut Session,
    ) -> Result<(Option<InitEcdhReturn>, Option<Vec<u8>>)> {
        let (metadata, envelope) = match body {
            Some(data) => {
                let envelope = Layer8Envelope::from_json_bytes(data).map_err(|e| {
                    error!("Failed to decode response: {e}, Data is :{}", String::from_utf8_lossy(data));
                    to_pingora_err(&e.to_string())
                })?;

                match envelope {
                    Layer8Envelope::WebSocket(payload) => {
                        let metadata = serde_json::from_value::<serde_json::Map<String, serde_json::Value>>(payload.metadata.clone())
                            .expect("we expect a json object as the metadata");
                        (metadata, Some(payload))
                    }

                    Layer8Envelope::Http(roundtrip) => {
                        let storage = Arc::clone(&self.http_storage);

                        // let storage = self.http_storage.read().unwrap();

                        // let storage = HTTP_INMEM_STORAGE.read().unwrap();

                        let keys = storage.lock().unwrap().keys.clone();
                        debug!("---------------------------------------------------------------");
                        debug!("Printing the storage keys: {:?}", keys);
                        debug!("---------------------------------------------------------------");

                        let client_uuid = session
                            .get_header("x-client-uuid")
                            .expect("we expect the x-client-uuid to be present in the headers")
                            .to_str()
                            .expect("all header values are expected to be in ascii");

                        let response_data = roundtrip
                            .decode()
                            .map_err(|e| to_pingora_err(&format!("Failed to decode response: {}", e)))?;

                        let shared_secret = keys.get(client_uuid).ok_or_else(|| {
                            error!("Failed to find shared secret for client uuid: {}", client_uuid);
                            to_pingora_err("Failed to find shared secret for client uuid")
                        })?;

                        let payload = shared_secret
                            .symmetric_decrypt(&response_data)
                            .map_err(|e| to_pingora_err(&format!("Failed to decrypt response: {}", e)))?;

                        // we expect the payload to be a json object of type Request
                        let resp =
                            serde_json::from_slice::<Request>(&payload).map_err(|e| to_pingora_err(&format!("Failed to decode response: {}", e)))?;

                        // updating the headers and the path uri to the service provider
                        let req_header = session.req_header_mut();
                        *req_header = RequestHeader::build(
                            Method::from_bytes(resp.method.as_bytes()).map_err(|e| to_pingora_err(&e.to_string()))?,
                            resp.url_path.unwrap_or("/".to_string()).as_bytes(),
                            Some(resp.body.len()),
                        )?;

                        resp.headers.iter().for_each(|(key, val)| {
                            req_header.append_header(key.clone(), val).expect("expected the header to be valid");
                        });

                        return Ok((None, Some(resp.body)));
                    }

                    Layer8Envelope::Raw(raw) => {
                        let storage = Arc::clone(&self.http_storage);

                        let client_uuid = session
                            .get_header("x-client-uuid")
                            .expect("we expect the x-client-uuid to be present in the headers")
                            .to_str()
                            .expect("all header values are expected to be in ascii");

                        let keys = storage.lock().unwrap().keys.clone();
                        let shared_secret = keys.get(client_uuid).ok_or_else(|| {
                            error!("Failed to find shared secret for client uuid: {}", client_uuid);
                            to_pingora_err("Failed to find shared secret for client uuid")
                        })?;

                        let payload = shared_secret
                            .symmetric_decrypt(&base64_enc_dec.decode(&raw).map_err(|e| to_pingora_err(&e.to_string()))?)
                            .map_err(|e| to_pingora_err(&e))?;

                        return Ok((None, Some(payload)));
                    }
                }
            }

            None => {
                if session.is_upgrade_req() {
                    return Err(to_pingora_err("we don't expect a websocket request to get here; report this as a bug"));
                }

                // we expect the metadata to be in the headers, so no need to decode the body
                let mut map = serde_json::Map::new();
                ["x-ecdh-init", "x-client-uuid", "mp-jwt"].iter().for_each(|val| {
                    if let Some(header_val) = session.get_header(*val) {
                        map.insert(
                            val.to_string(),
                            header_val.to_str().expect("all header values are expected to be in ascii").into(),
                        );
                    }
                });

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

    debug!("---------------------------------------------------------------");
    debug!("InMemStorage: {:?}", storage);
    debug!("---------------------------------------------------------------");

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
