use pingora_core::{apps::ServerApp, server::{configuration::Opt, Server}};

mod proxy;

const LAYER8_PORT: &'static str = "LAYER8_PORT";

fn main() {
    dotenv::dotenv().ok();
    let port = std::env::var(LAYER8_PORT).unwrap_or("80".to_string());
    // .expect(
    //     "LAYER8_PORT environment variable is required.
    //     Example:
    //     LAYER8_PORT=8080 ./binary", // we rather panic now for a missing env var
    // );

    // read command line arguments
    let opt = Opt::parse_args();
    let mut server = Server::new(Some(opt)).unwrap();
    server.bootstrap();

    ServerApp

    let mut middleware = pingora_proxy::http_proxy_service(&server.configuration, proxy::Layer8Proxy);

    middleware.add_tcp(&format!("0.0.0.0:{}", port));
    server.add_service(middleware);
    server.run_forever()
}
