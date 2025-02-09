use ewebsock;

// const express = require('express');
// const http = require('http');
// const socketIo = require('socket.io');

// const app = express();
// const server = http.createServer(app);
// const io = socketIo(server);

// io.on('connection', (socket) => {
//   console.log('New client connected');

//   socket.on('message', (message) => {
//     console.log('Message received:', message);
//     io.emit('message', message); // Broadcast the message to all clients
//   });

//   socket.on('disconnect', () => {
//     console.log('Client disconnected');
//   });
// });

// server.listen(4000, () => {
//   console.log('Server is running on port 4000');
// });

pub struct WebsocketClient(String);

pub struct WebSocketConnection {
    sender: ewebsock::WsSender,
    receiver: ewebsock::WsReceiver,
}

impl WebsocketClient {
    /// Create a new websocket client.
    ///
    /// Before matures for stable release, provide an options struct to configure the client.
    pub fn new(url: String, options: ewebsock::Options) -> Result<Self, String> {
        let options = ewebsock::Options::default();
        // see documentation for more options
        let (mut sender, receiver) = ewebsock::connect("ws://example.com", options).unwrap();
        sender.send(ewebsock::WsMessage::Text("Hello!".into()));
        while let Some(event) = receiver.try_recv() {
            println!("Received {:?}", event);
        }

        todo!()
    }

    pub fn on(op: &str) {}

    fn on_connection(&self) {
        todo!()
    }

    fn on_message(&self, message: &[u8]) {
        todo!()
    }

    fn on_disconnect(self) {
        todo!()
    }
}
