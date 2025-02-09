use forward_proxy::run_proxy_server;
use log::{error, warn};

fn main() {
    dotenv::dotenv().ok();

    let port = std::env::var("PORT")
        .map(|v| match v.parse::<u16>() {
            Ok(port) => port,
            Err(_) => {
                error!("Failed to parse PORT environment variable. Using default port 8080");
                panic!("Failed to parse PORT environment variable");
            }
        })
        .unwrap_or_else(|_| {
            warn!("PORT environment variable is not set. Using default port 8080");
            8080
        });

    let service_port = std::env::var("SERVICE_PORT")
        .map(|v| match v.parse::<u16>() {
            Ok(port) => port,
            Err(_) => {
                error!("Failed to parse SERVICE_PORT environment variable. Using default port 8080");
                panic!("Failed to parse SERVICE_PORT environment variable");
            }
        })
        .unwrap_or_else(|_| {
            warn!("SERVICE_PORT environment variable is not set. Using default port 8080");
            panic!("SERVICE_PORT environment variable is not set");
        });

    run_proxy_server(port, service_port, false);
}
