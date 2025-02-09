use std::net::{Ipv4Addr, SocketAddrV4};

use tokio::{net::TcpListener, sync::oneshot};

async fn test_http_call() {}

async fn test_server(closing_signal: oneshot::Receiver<()>, port: &mut u16) {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|err| err.to_string())
        .expect("Failed to bind to random port");

    *port = listener.local_addr().unwrap().port();

    tokio::select! {
        Ok((socket, _)) = listener.accept() => {
            println!("Server accepted a connection");
            tokio::spawn(async move {
                // lets echo whatever we receive
                
            });
        },
        _ = closing_signal => {
            println!("Server is closing");
        }

    }
}
