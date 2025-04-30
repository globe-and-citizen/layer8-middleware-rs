use clap::Parser;
use log::{debug, error, info};

use reverse_proxy::run_proxy_server;

mod daemonize;
use daemonize::{add_proxy, get_all_proxies, get_proxy, prepare_bookkeeping, remove_proxy};
use tokio::select;

#[derive(Parser, Debug)]
#[command(name = "l8proxy")]
#[command(version, about, long_about = None)]
enum Cli {
    /// Starts the reverse-proxy server
    Start {
        /// Port to forward the requests to after processing
        /// Example: --service-port=8090
        #[arg(short, long)]
        service_port: u16,

        /// Port to listen for incoming requests; default is 8080
        /// Example: --port=8080
        #[arg(short, long)]
        port: Option<u16>,

        /// Starts the reverse-proxy server in the background if set; default is false
        #[arg(short, long)]
        detach: bool,

        /// Log level to use; default is INFO
        /// Example: --log-level=DEBUG
        /// Possible values: FATAL, ERROR, WARN, INFO, DEBUG, TRACE
        #[arg(short, long)]
        log_level: Option<String>,

        /// Path to write logs to if provided
        /// Example: --log-file=/path/to/file.log
        #[arg(long)]
        log_file: Option<String>,
    },
    /// Stops the reverse-proxy server if it is running in the background
    Stop {
        /// Proxy port to stop; if not provided, all running proxies are stopped.
        #[arg(short, long)]
        port: Option<u16>,
    },

    /// Lists all running reverse-proxy servers
    List,
}

#[tokio::main]
async fn main() {
    // if cfg!(debug_assertions) {
    std::env::set_var("RUST_LOG", "DEBUG");
    // } else {
    // std::env::set_var("RUST_LOG", "INFO");
    // }

    env_logger::init();

    prepare_bookkeeping();

    match Cli::parse() {
        Cli::Start {
            service_port,
            port,
            detach,
            log_level,
            log_file: _, // todo: implement log file writing
        } => {
            let port = port.unwrap_or_else(|| {
                info!("Port not provided. Using default port: 8080");
                8080
            });

            if let Some(level) = log_level {
                std::env::set_var("RUST_LOG", level);
            }

            match detach {
                true => {
                    println!("Starting reverse-proxy server at port: {} in the background", port);
                    tokio::task::spawn_blocking(move || {
                        add_proxy(port, service_port).unwrap();
                        run_proxy_server(port, service_port, detach);
                    });
                }
                false => {
                    let proc = tokio::task::spawn_blocking(move || {
                        add_proxy(port, service_port).unwrap();
                        run_proxy_server(port, service_port, detach);
                    });

                    select! {
                        _ = proc => {
                            debug!("Proxy server stopped");
                        }

                        _ = tokio::signal::ctrl_c() => {
                            info!("Received interrupt signal. Stopping the proxy server");
                            remove_proxy(port).unwrap();
                        }
                    }
                }
            }
        }

        Cli::Stop { port } => match port {
            Some(port) => {
                println!("Stopping reverse-proxy server at port: {}", port);
                let proxy = match get_proxy(port) {
                    Ok(val) => match val {
                        Some(proxy) => proxy,
                        None => {
                            error!("No proxy found at port: {}", port);
                            return;
                        }
                    },
                    Err(err) => {
                        error!("{}", err);
                        return;
                    }
                };

                let resp = reqwest::Client::new()
                    .get(format!("http://localhost:{}/", proxy.port))
                    .header("l8-stop-signal", 1)
                    .send()
                    .await
                    .unwrap();

                // lets log the response code
                info!("Response code: {}", resp.status());

                // ensure the response is Accepted
                if resp.status() != reqwest::StatusCode::ACCEPTED {
                    error!("Failed to stop reverse-proxy server at port: {}", proxy.port);
                }

                remove_proxy(port).unwrap();
            }
            None => {
                info!("Stopping all running reverse-proxy servers");
                let proxies = match get_all_proxies() {
                    Ok(val) => val,
                    Err(err) => {
                        error!("{}", err);
                        return;
                    }
                };

                for proxy in proxies {
                    info!("-------------------------");
                    info!("Port: {}", proxy.port);
                    info!("Service port: {}", proxy.service_port);

                    let result_ = reqwest::Client::new()
                        .get(format!("http://localhost:{}/", proxy.port))
                        .header("l8-stop-signal", 1)
                        .send()
                        .await;

                    match result_ {
                        Ok(resp) => {
                            // lets log the response code
                            info!("\nStop HTTP code: {}", resp.status());

                            // ensure the response is Accepted
                            if resp.status() != reqwest::StatusCode::ACCEPTED {
                                error!("Failed to stop reverse-proxy server with process id: {}", proxy.port);
                            }
                        }

                        Err(err) => {
                            if !reqwest::Error::is_request(&err) {
                                error!("Failed to stop reverse-proxy server with process id: {}. Error: {}", proxy.port, err);
                            }
                        }
                    }
                }
            }
        },

        Cli::List => {
            info!("Listing all running reverse-proxy servers");
            let proxies = match get_all_proxies() {
                Ok(val) => val,
                Err(err) => {
                    error!("{}", err);
                    return;
                }
            };

            if proxies.is_empty() {
                println!("No running l8proxy servers found");
                return;
            }

            for proxy in proxies {
                println!("-------------------------");
                println!("Port: {}", proxy.port);
                println!("Service port: {}", proxy.service_port);
            }
        }
    }
}
