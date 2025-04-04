use env_logger::{Env, Target};
use forward_proxy::run_proxy_server;
use log::{error, info, warn, LevelFilter};
use std::io::Write;

fn main() {
    dotenv::dotenv().ok();

    env_logger::Builder::from_env(Env::default())
        .format(|buf, record| {
            writeln!(
                buf,
                "{}:{} {} [{}] - {}",
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                chrono::Local::now().format("%Y-%m-%dT%H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .target(Target::Stdout)
        .filter(Some("logger_example"), LevelFilter::Debug)
        .init();

    let port = std::env::var("PORT")
        .map(|v| match v.parse::<u16>() {
            Ok(port) => {
                info!("Using port: {}", port);
                port
            }
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
