//! This is the API interface for the layer8 forward proxy.

use std::collections::HashMap;

use async_trait::async_trait;
use bytes::Bytes;
use layer8_middleware_rs::middleware::get_arbitrary_boundary;
use layer8_primitives::crypto::base64_to_jwk;
use log::{error, info};
use pingora::http::ResponseHeader;
use pingora_core::prelude::Opt;
use pingora_core::server::Server;
use pingora_core::{prelude::HttpPeer, Result};
use pingora_proxy::{ProxyHttp, Session};

use layer8_middleware_rs::{process_data, InMemStorage};
use serde_json::Number;

struct Layer8Proxy {
    service_port: u16,
}

#[async_trait]
impl ProxyHttp for Layer8Proxy {
    type CTX = InMemStorage;
    fn new_ctx(&self) -> Self::CTX {
        Default::default()
    }

    // determines only the upstream peer
    async fn upstream_peer(&self, _: &mut Session, _: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        let peer = Box::new(HttpPeer::new(("localhost", self.service_port), false, "one.one.one.one".to_string()));
        Ok(peer)
    }

    // handle incoming requests, we can filter requests here and return a response if we want
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        if let Some(val) = session.get_header("x-tunnel") {
            let value = val.to_str().map_err(|e| to_pingora_err(&e.to_string()))?;
            if value.eq("true") {
                ecdh_tunnel(ctx, session).await?;
                return Ok(true);
            }
        }

        Ok(false)
    }
}

/// This is a blocking operation that runs the proxy server. The server is stopped when it encounters an error or interrupt signals.
pub fn run_proxy_server(port: u16, service_port: u16, daemonize: bool) {
    let mut server = Server::new(Opt {
        daemon: daemonize,
        ..Default::default()
    })
    .unwrap();

    server.bootstrap();

    let mut middleware = pingora_proxy::http_proxy_service(&server.configuration, Layer8Proxy { service_port });

    middleware.add_tcp(&format!("0.0.0.0:{}", port));
    server.add_service(middleware);
    server.run_forever()
}

async fn ecdh_tunnel(ctx: &mut InMemStorage, session: &mut pingora_proxy::Session) -> Result<()> {
    let x_ecdh_init = session.get_header("x-ecdh-init");
    let x_client_uuid = session.get_header("x-client-uuid");

    // we assume the tunnel is not established if `x-ecdh-init` and `x_client_uuid` are not present
    if x_ecdh_init.is_none() || x_client_uuid.is_none() {
        return init_ecdh_tunnel(ctx, session).await.map_err(|e| {
            error!("error initializing ECDH tunnel: {e}");
            Box::new(to_pingora_err(&e))
        });
    }

    let symmetric_key = {
        let val = ctx.keys.get(
            x_client_uuid
                .expect("previous assertion; qed")
                .to_str()
                .map_err(|e| to_pingora_err(&e.to_string()))?,
        );

        match val {
            Some(shared_secret) => shared_secret,
            None => {
                return init_ecdh_tunnel(ctx, session).await.map_err(|e| {
                    error!("error initializing ECDH tunnel: {e}");
                    Box::new(to_pingora_err(&e))
                })
            }
        }
    };

    let mp_jwt = {
        let val = ctx.jwts.get(
            x_client_uuid
                .expect("previous assertion; qed")
                .to_str()
                .map_err(|e| to_pingora_err(&e.to_string()))?,
        );

        match val {
            Some(mp_jwk) => mp_jwk,
            None => {
                return init_ecdh_tunnel(ctx, session).await.map_err(|e| {
                    error!("error initializing ECDH tunnel: {e}");
                    Box::new(to_pingora_err(&e))
                });
            }
        }
    };

    // let sym_key = serde_json::to_string(&symmetric_key).expect("expected symmetric key to be serializable to a string; qed");

    // lets get the body; we expect a json body
    let body = session.read_request_body().await?.ok_or_else(|| to_pingora_err("expected a body"))?;

    match process_data(&body, &symmetric_key) {
        Ok(processed_req) => {
            // we assume the payload is json
            let req_body = match serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&processed_req.body) {
                Ok(val) => val,
                Err(err) => {
                    if !processed_req.body.is_empty() {
                        error!("error decoding body: {err}");
                        session.write_response_header(Box::new(ResponseHeader::build(500, None)?), true).await?;
                        return session.write_response_body(Some(Bytes::from_static(b"error decoding body")), true).await;
                    }

                    serde_json::Map::new()
                }
            };

            match processed_req.headers.get("content-type") {
                // this needs rework to propagate the client frontend's provided "boundary"
                Some(x) if x.eq("application/layer8.buffer+json") => {
                    let mut header = ResponseHeader::build(200, None)?;
                    let form_data = match convert_body_to_form_data_no_web_api(&req_body) {
                        Ok(_) => Bytes::new(),
                        Err(err) => {
                            error!("error decoding file buffer: {err}");
                            header.set_status(500)?;
                            session.write_response_header(Box::new(header), false).await?;
                            return session
                                .write_response_body(Some(Bytes::from(format!("Could not decode file buffer: {err}"))), true)
                                .await;
                        }
                    };

                    header.insert_header("content-type", &format!("multipart/form-data; boundary={}", get_arbitrary_boundary()))?;
                    session.write_response_header(Box::new(header), false).await?;
                    session.write_response_body(Some(form_data), true).await
                }

                _ => {
                    let body = match processed_req.body.is_empty() {
                        true => None,
                        false => Some(Bytes::from(
                            serde_json::to_vec(&req_body).expect("expected the body to be serializable to a valid json object; qed"),
                        )),
                    };

                    session.write_response_body(body, true).await
                }
            }
        }

        Err(resp) => {
            error!("Issue processing data!");
            return session
                .write_response_header(Box::new(ResponseHeader::build(resp.status, None)?), true)
                .await;
        }
    }
}

async fn init_ecdh_tunnel(ctx: &mut InMemStorage, session: &mut pingora_proxy::Session) -> Result<(), String> {
    // check the required headers are present
    let mut missing = Vec::new();
    let mut invalid = Vec::new();
    for i in ["x-ecdh-init", "x-client-uuid", "mp-jwt"] {
        match session.get_header(i) {
            Some(val) => {
                _ = val.to_str().map_err(|_| {
                    invalid.push(i);
                });
            }

            None => missing.push(i),
        }
    }

    if !missing.is_empty() {
        missing.sort();
        return Err(format!("Missing required headers: {:?}", missing.join(", ")));
    }

    if !invalid.is_empty() {
        return Err(format!("Invalid headers: {:?}", invalid.join(", ")));
    }

    let user_pub_jwk = {
        let user_pub_jwk = session
            .get_header("x-ecdh-init")
            .expect("we know the value exists; qed")
            .to_str()
            .map_err(|e| format!("failure to decode userPubJwk as string: {e}"))?;

        base64_to_jwk(user_pub_jwk).map_err(|e| format!("failure to decode userPubJwk: {e}"))?
    };

    let shared_secret = ctx
        .ecdh
        .get_private_key()
        .get_ecdh_shared_secret(&user_pub_jwk)
        .map_err(|e| format!("unable to get ECDH shared secret: {e}"))?;

    let client_uuid = session
        .get_header("x-client-uuid")
        .expect("we know the value exists; qed")
        .to_str()
        .map_err(|e| format!("failed to decode client uuid as string: {e}"))?;

    // adding the shared secret to the keys
    ctx.keys.add(client_uuid, shared_secret.clone());
    let b64_pub_key = ctx.ecdh.get_public_key().export_as_base64();

    let mp_jwt = session
        .get_header("mp-jwt")
        .expect("we know the value exists; qed")
        .to_str()
        .map_err(|e| format!("failed to decode mp-jwt as string: {e}"))?;

    // saving the mp-jwt to the jwts
    ctx.jwts.add(client_uuid, mp_jwt);

    info!("ECDH Successfully Completed!");
    let mut header = ResponseHeader::build(200, None).unwrap();
    header.insert_header("mp-JWT", mp_jwt).unwrap();
    header.insert_header("server_pubKeyECDH", &b64_pub_key).unwrap();
    session.write_response_body(Some(Bytes::from(b64_pub_key)), true).await.unwrap();

    Ok(())
}

// consider returning a Vec<u8> blob with well-formed FormData
fn convert_body_to_form_data_no_web_api(req_body: &serde_json::Map<String, serde_json::Value>) -> Result<HashMap<String, serde_json::Value>, String> {
    let populate_form_data = |k: &str, val: &serde_json::Map<String, serde_json::Value>| -> Result<serde_json::Value, String> {
        let _type = val
            .get("_type")
            .expect("expected val to have a _type key")
            .as_str()
            .expect("expected _type to be a string");

        match _type {
            x if x.eq("File") => {
                // more work to include all metadata information

                let buff = val
                    .get("buff")
                    .ok_or("expected File to have a buff key".to_string())?
                    .as_str()
                    .expect("expected value to be parsable as string");

                let _name = val
                    .get("name")
                    .ok_or("expected File to have a name key".to_string())?
                    .as_str()
                    .expect("expected name to be parsable as string");

                Ok(serde_json::Value::String(buff.to_string()))
            }

            x if x.eq("String") => Ok(serde_json::Value::String(x.to_string())),
            x if x.eq("Number") => Ok(serde_json::Value::Number(
                Number::from_f64(x.parse::<f64>().expect("expected the value to be a valid number; qed"))
                    .expect("expected the value to be a valid number; qed"),
            )),
            x if x.eq("Boolean") => Ok(serde_json::Value::Bool(
                x.parse::<bool>().expect("expected the value to be a valid boolean; qed"),
            )),
            _ => Err("expected _type to be one of the following: File, String, Number, Boolean".to_string()),
        }
    };

    let mut form_data = HashMap::new();
    for (k, v) in req_body {
        if let serde_json::Value::Object(val) = v {
            form_data.insert(k.clone(), populate_form_data(k, val)?);
        }
    }

    Ok(form_data)
}

fn to_pingora_err(val: &str) -> pingora_core::Error {
    todo!("convert string to pingora error")
}

#[test]
fn test_tunnel() {
    todo!()
}
