//! This is the API interface for the layer8 forward proxy.
use core::default::Default;
use std::time::Duration;

use async_trait::async_trait;
use base64::{self, engine::general_purpose::URL_SAFE as base64_enc_dec, Engine as _};
use bytes::Bytes;
use http::{response, Method};
use log::{debug, error, info};
use pingora::{
    http::{RequestHeader, ResponseHeader},
    modules::http::{compression::ResponseCompressionBuilder, HttpModules},
};
use pingora_core::{
    prelude::{HttpPeer, Opt, Result},
    server::Server,
};
use pingora_proxy::{ProxyHttp, Session};
use serde_json::json;

mod http_filters;
mod memory;
mod middleware;
mod websocket_filters;
use layer8_middleware_rs::{Ecdh, InMemStorage, InitEcdhReturn};
use layer8_primitives::{
    crypto::{base64_to_jwk, generate_key_pair, Jwk, KeyUse},
    types::{Layer8Envelope, Request, Response, WebSocketPayload},
};
use memory::{ConnectionContext, HTTP_INMEM_STORAGE};
use websocket_filters::{construct_raw_websocket_frame, parse_payload_from_raw_frame_bytes};

/// This is the reverse proxy instance for the layer8 middleware.
struct Layer8Proxy {
    service_port: u16,
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
            init_echo_payload: None,
            roundtrip_response_cache: Response::default(),
        }
    }

    // // These modules allow us to provide the order of operations as a side effect since they are ran in order
    // fn init_downstream_modules(&self, modules: &mut HttpModules) {
    //     // Add disabled downstream compression module by default
    //     modules.add_module(ResponseCompressionBuilder::enable(0));
    //     // modules.add_module();
    // }

    async fn request_filter(&self, session: &mut Session, _: &mut Self::CTX) -> Result<bool>
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
        debug!("---------------- CallStack: request_body_filter ----------------");

        // we only need to process the body if it is an upgrade request, else this can be done in the request_filter
        // we assume a websocket connection, other upgrades are not supported
        if session.is_upgrade_req() {
            let data = match body {
                Some(val) => val,
                None => {
                    info!("body is empty");
                    return Ok(());
                }
            };

            let encoded_data = parse_payload_from_raw_frame_bytes(data).map_err(|e| to_pingora_err(&e))?;
            match ecdh_exchange(ctx, &encoded_data, session).await? {
                // tunnel is being set up, clear the body
                (Some(init_value), None) => {
                    let payload = Layer8Envelope::WebSocket(WebSocketPayload {
                        payload: None,
                        metadata: json!({
                            "server_pubKeyECDH": init_value.server_public_key,
                            "mp-jwt": init_value.mp_jwt
                        }),
                    })
                    .to_json_bytes();

                    ctx.init_echo_payload = Some(Bytes::from(payload));
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

        // we don't process requests that are not part of the tunnel
        if session.get_header("x-tunnel").is_none() && session.get_header("x-client-uuid").is_none() {
            return Ok(());
        }

        let mut acc_body = {
            let mut val = Vec::new();
            if let Some(body) = body {
                val.extend_from_slice(&body);
            }
            val
        };

        // loading the entire response to in-memory, maybe do chunked enc/dec for the protocol?
        // todo @Osoro, Ref:<https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Transfer-Encoding>
        loop {
            let data = session.read_request_body().await?;
            match data {
                Some(val) => {
                    acc_body.extend_from_slice(&val);
                    if val.len() == 0 {
                        // todo: check condition behavior at runtime and check-off
                        break;
                    }
                }
                None => break,
            }
        }

        match ecdh_exchange(ctx, &acc_body, session).await? {
            // tunnel is being set up, clear the body
            (Some(val), None) => {
                // let's respond without even sending this to the server
                let mut header = ResponseHeader::build(200, None)?;
                header.append_header("mp-JWT", val.mp_jwt.clone())?;
                header.append_header("server_pubKeyECDH", val.server_public_key.clone())?;
                session.write_response_header(Box::new(header), false).await?;

                let server_public_key = val.server_public_key.clone();
                session
                    .write_response_body(
                        Some(Bytes::from(Layer8Envelope::Raw(server_public_key.as_bytes().to_vec()).to_json_bytes())),
                        false,
                    )
                    .await?;

                info!("ECDH Successfully Completed!");
            }

            // tunnel already setup; we only need to rewrite the response body
            (None, Some(val)) => {
                *body = Some(Bytes::from(val));
            }

            _ => {
                return Err(to_pingora_err("Error processing data"));
            }
        }

        Ok(())
    }

    fn response_body_filter(&self, session: &mut Session, body: &mut Option<Bytes>, _: bool, ctx: &mut Self::CTX) -> Result<Option<Duration>>
    where
        Self::CTX: Send + Sync,
    {
        debug!("---------------- CallStack: response_body_filter ----------------");

        if session.is_upgrade_req() {
            if let Some(init_echo_payload) = ctx.init_echo_payload.as_ref() {
                debug!("---------------------------------------------------------------");
                debug!("Sending ECDH Init Payload: {:?}", String::from_utf8_lossy(init_echo_payload));
                debug!("---------------------------------------------------------------");

                let output = construct_raw_websocket_frame(init_echo_payload, false).map_err(|e| to_pingora_err(&e))?;
                *body = Some(Bytes::from(output));
                ctx.init_echo_payload = None;
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

        // todo @Osoro: we assume the body is complete, this may be chunked or not wholly complete
        let mut unencrypted_body = Vec::new();
        if let Some(body) = body {
            unencrypted_body.extend_from_slice(body);
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

            session.write_response_header(Box::new(response_header), false).await;
        }

        Ok(None)
    }

    async fn response_filter(&self, session: &mut Session, upstream_response: &mut ResponseHeader, ctx: &mut Self::CTX) -> Result<()> {
        todo!()
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

// if (Some(val), None) =>  the data from the client is for the the init tunnel handshake
// (None, Some(val)) => the data from the client is from a subsequent call after the tunnel had been established
async fn ecdh_exchange(ctx: &mut ConnectionContext, data: &[u8], session: &mut Session) -> Result<(Option<InitEcdhReturn>, Option<Vec<u8>>)> {
    let envelope = Layer8Envelope::from_json_bytes(data).map_err(|e| {
        error!("Failed to decode response: {e}, Data is :{}", String::from_utf8_lossy(data));
        to_pingora_err(&e.to_string())
    })?;

    let metadata = match &envelope {
        Layer8Envelope::WebSocket(payload) => serde_json::from_value::<serde_json::Map<String, serde_json::Value>>(payload.metadata.clone())
            .expect("we expect a json object as the metadata"),

        // we have the the metadata data in the headers
        Layer8Envelope::Http(_) | Layer8Envelope::Raw(_) => {
            let mut map = serde_json::Map::new();
            ["x-ecdh-init", "x-client-uuid", "mp-jwt"].iter().for_each(|val| {
                if let Some(header_val) = session.get_header(*val) {
                    map.insert(
                        val.to_string(),
                        header_val.to_str().expect("all header values are expected to be in ascii").into(),
                    );
                }
            });

            map
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

        return init_ecdh_tunnel(ctx, session, x_ecdh_init, x_client_uuid, mp_jwt).map(|val| (Some(val), None::<Vec<u8>>));
    }

    let client_uuid = x_client_uuid.expect("expected x-client-uuid to be present; report this as a bug");

    // we need to get the shared secret from the in memory storage, this might be different if the connection is a duplex
    // connection or not.
    let shared_secret = |is_duplex_connection| -> Result<Jwk> {
        let storage = match is_duplex_connection {
            true => &ctx.persistent_storage,
            false => &HTTP_INMEM_STORAGE.lock().unwrap(),
        };

        storage
            .keys
            .get(client_uuid)
            .ok_or_else(|| {
                error!("Failed to find shared secret for client uuid: {}", client_uuid);
                to_pingora_err("Failed to find shared secret for client uuid")
            })
            .cloned()
    };

    // at this point we retrieve our keys and decrypt the data in the payload section
    let payload = match envelope {
        Layer8Envelope::WebSocket(ws_data) => {
            if ws_data.payload.is_none() {
                return Err(to_pingora_err("expected a payload in the websocket envelope"));
            }

            shared_secret(true)?
                .symmetric_decrypt(
                    &base64_enc_dec
                        .decode(ws_data.payload.expect("expected the payload to be present"))
                        .map_err(|e| to_pingora_err(&e.to_string()))?,
                )
                .map_err(|e| to_pingora_err(&e))?
        }

        Layer8Envelope::Http(roundtrip) => {
            let response_data = roundtrip
                .decode()
                .map_err(|e| to_pingora_err(&format!("Failed to decode response: {}", e)))?;

            let payload = shared_secret(false)?
                .symmetric_decrypt(&response_data)
                .map_err(|e| to_pingora_err(&format!("Failed to decrypt response: {}", e)))?;

            // we expect the payload to be a json object of type Request
            let resp = serde_json::from_slice::<Request>(&payload).map_err(|e| to_pingora_err(&format!("Failed to decode response: {}", e)))?;

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

            resp.body
        }

        Layer8Envelope::Raw(raw) => {
            let payload = shared_secret(false)?
                .symmetric_decrypt(&base64_enc_dec.decode(&raw).map_err(|e| to_pingora_err(&e.to_string()))?)
                .map_err(|e| to_pingora_err(&e))?;

            payload
        }
    };

    Ok((None, Some(payload)))
}

fn init_ecdh_tunnel(
    ctx: &mut ConnectionContext,
    session: &mut Session,
    x_ecdh_init: &str,
    x_client_uuid: &str,
    mp_jwt: &str,
) -> Result<InitEcdhReturn> {
    let establish_tunnel = |persistent_storage: &mut InMemStorage| -> Result<InitEcdhReturn> {
        let user_pub_jwk = base64_to_jwk(x_ecdh_init).map_err(|e| to_pingora_err(&format!("failure to decode userPubJwk: {e}")))?;

        debug!("---------------------------------------------------------------");
        debug!("InMemStorage: {:?}", persistent_storage);
        debug!("---------------------------------------------------------------");

        let shared_secret = persistent_storage
            .ecdh
            .get_private_key()
            .get_ecdh_shared_secret(&user_pub_jwk)
            .map_err(|e| to_pingora_err(&e))?;

        // adding the shared secret to the keys
        persistent_storage.keys.add(x_client_uuid, shared_secret.clone());

        let b64_shared_secret = shared_secret.export_as_base64();
        let b64_pub_key = persistent_storage.ecdh.get_public_key().export_as_base64();

        // saving the mp-jwt to the jwts
        persistent_storage.jwts.add(x_client_uuid, mp_jwt);

        Ok(InitEcdhReturn {
            shared_secret: b64_shared_secret,
            server_public_key: b64_pub_key,
            mp_jwt: mp_jwt.to_string(),
        })
    };

    if session.is_upgrade_req() {
        return establish_tunnel(&mut ctx.persistent_storage);
    }

    let ref_count = HTTP_INMEM_STORAGE.clone();
    let mut storage = ref_count.lock().unwrap();
    establish_tunnel(&mut storage)
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
