//! This is the API interface for the layer8 forward proxy.

use std::process::Command;

use async_trait::async_trait;
use pingora_core::prelude::Opt;
use pingora_core::server::Server;
use pingora_core::{prelude::HttpPeer, Result};
use pingora_proxy::ProxyHttp;

struct Layer8Proxy {
    service_port: u16,
}

#[async_trait]
impl ProxyHttp for Layer8Proxy {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(&self, session: &mut pingora_proxy::Session, _: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        if let Some(_) = session.get_header("l8-stop-signal") {
            if cfg!(target_os = "windows") {
                Command::new("taskkill")
                    .arg("/F")
                    .arg("/IM")
                    .arg(format!(":{}", self.service_port))
                    .spawn()
                    .expect("Failed to send SIGTERM signal to the service");
            } else if cfg!(unix) {
                Command::new("pkill")
                    .arg("-SIGTERM")
                    .arg("-f")
                    .arg(format!(":{}", self.service_port))
                    .spawn()
                    .expect("Failed to send SIGTERM signal to the service");
            } else {
                panic!("Unsupported OS");
            }

            panic!("Received stop signal. Stopping the server");
        }

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

    server.bootstrap();

    let mut middleware = pingora_proxy::http_proxy_service(&server.configuration, Layer8Proxy { service_port });

    middleware.add_tcp(&format!("0.0.0.0:{}", port));
    server.add_service(middleware);
    server.run_forever()
}
