use async_trait::async_trait;
use pingora_core::{prelude::HttpPeer, Result};
use pingora_proxy::ProxyHttp;
use tokio;

pub trait Context {
    // Placeholder for now
    fn metadata(&self) -> Vec<u8>;

    // Placeholder for now
    fn payload(&self) -> Vec<u8>;
}

pub(crate) struct Layer8Proxy;

#[async_trait]
impl ProxyHttp for Layer8Proxy {
    type CTX = Box<dyn Context>; // todo?: This is a placeholder for now

    fn new_ctx(&self) -> Self::CTX {
        todo!() // This is created per request; so we need to implement this after we have a better understanding of the context
    }

    async fn upstream_peer(&self, session: &mut pingora_proxy::Session, _: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        let backend_url = session
            .get_header("X-Forwarded-Host")
            .unwrap_or_else(|| session.get_header("Host").expect("X-Forwarded-Host or Host header is required"))
            .to_str()
            .map_err(|e| {
                log::error!("Failed to convert header to string: {}", e);
                pingora_core::Error::create(
                    pingora_core::ErrorType::Custom("Failed to convert header to string"),
                    pingora_core::ErrorSource::Upstream,
                    None,
                    None,
                )
            })?;

        let mut res = tokio::net::lookup_host(backend_url).await.map_err(|e| {
            log::error!("Failed to resolve backend host: {}", e);
            pingora_core::Error::create(
                pingora_core::ErrorType::Custom("Failed to resolve backend host"),
                pingora_core::ErrorSource::Upstream,
                None,
                None,
            )
        })?;

        let addr = res.next().ok_or_else(|| {
            log::error!("Failed to resolve backend host: no address found");
            pingora_core::Error::create(
                pingora_core::ErrorType::Custom("Failed to resolve backend host: no address found"),
                pingora_core::ErrorSource::Upstream,
                None,
                None,
            )
        })?;

        let peer = Box::new(HttpPeer::new(addr, false, addr.to_string()));
        Ok(peer)
    }
}
