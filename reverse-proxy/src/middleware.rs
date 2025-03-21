// use bytes::Bytes;

// use http::{header, HeaderMap};
// use log::error;
// use pingora::http::ResponseHeader;
// use pingora_proxy::Session;

// use layer8_middleware_rs::{initialize_ecdh, Ecdh, InMemStorage, InitEcdhReturn};

// pub struct Context {
//     pub persistent_data: InMemStorage,
//     pub init_ecdh_payload: Option<Bytes>,
// }

// /// This function is middleware that is used to initialize the ECDH key exchange between the client and the server.
// /// <div class="warning">It is not equipped to handle duplex connections!</div>
// pub async fn middleware(ctx: &mut Context, session: &mut Session) {
//     let ok = session.read_request().await.expect("todo");
//     if !ok {
//         return;
//     }

//     let headers_map = {
//         let req_header = session.req_header();
//         req_header.headers.clone()
//     };

//     if !headers_map.contains_key("x-tunnel") || headers_map.contains_key("x-client-uuid") {
//         return;
//     }

//     let body = session.read_request_body().await;

//     let init_ecdh = |req_body: &Bytes| async {
//         match initialize_ecdh(&headers_map, &mut ctx.persistent_data) {
//             Ok(res) => {
//                 // session.write_response_header(Box::new(ResponseHeader::), end_of_stream)
//                 todo!("write response header");
//             }
//             Err(err) => {
//                 error!("{}", err);
//                 session
//                     .write_response_header(Box::new(ResponseHeader::build(500, None).unwrap()), true)
//                     .await;

//                 session.write_response_body(Some(), end_of_stream)

//                 return;
//             }
//         }
//     };

//     session.write_response_body(body, end_of_stream)
// }
