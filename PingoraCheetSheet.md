# Pingora Cheet Sheet

This is companion documentation for the examples here: <https://github.com/cloudflare/pingora/tree/main/pingora-proxy/examples>

This cheat sheet is data from some examples I have used and things I learnt at runtime when working with Pingora through trial and error.
Please help contribute some if you have more examples or gotchas to add to reduce paper-cuts and bad dev experiences.

1. Gotcha: making sure you're capturing the entire request payload

    If we want to interact with the request in Pingora we implement this method:

    ```rust
    async fn request_filter<Self::CTX: Send + Sync>(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool>{
        // code goes here...
        Ok(false)
    }
    ```

    So payloads can be large, if you're dealing with small payloads you can get away with just calling:

    ```rust
    let body = session.request_body().await?;
    ```

    If you're dealing with large payloads you need to call the method iteratively until it yields an `Ok(None)`:

    ```rust
    let mut body = Vec::new();
    loop {
        match session.request_body().await? {
            Some(chunk) => body.extend_from_slice(&chunk),
            None => break,
        }
    }
    ```

2. Gotcha: content-length header gotcha

    If you want to respond to requests at the proxy level for reasons ranging from it acting as a cache to just wanting to process requests without hitting the server, you can do so by returning `Ok(true)` in the `request_filter` method:

    ```rust
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool>
        where
            Self::CTX: Send + Sync,
        {
            // Process the request without hitting the server
            Ok(true)
        }
    ```

    Below is an echo server equivalent, make sure to include the `Content-Length` header (you'll notice I use the first gotcha here to capture the request body):

    ```rust
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool>
        where
            Self::CTX: Send + Sync,
        {
            let mut body = Vec::new();
            loop {
                match session.request_body().await? {
                    Some(chunk) => body.extend_from_slice(&chunk),
                    None => break,
                }
            }

            // ... do some manipulation to the body maybe

            let new_body = "Hello, World!";
            let mut header = ResponseHeader::build(200, None)?;
            header.append_header("Content-Length", new_body.len().to_string());
            session.write_response_header_ref(&header).await?;
            session
                .write_response_body(Some(Bytes::from(new_body.bytes())), true)
                .await?;
        }
    }
    ```

    The `Content-Length` is not implicitly added so other servers may not respond correctly if it's missing. A Go server always looks for an EOF error to determine the end of the request body, so make sure to include it.

3. Gotcha: modifying a response from the server.
    If you want to modify the response from the server, you can do so in the `response_body_filter` method:

    ```rust
    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>>
    where
        Self::CTX: Send + Sync,
    {
        // buffer the data
        if let Some(b) = body {
            ctx.buffer.extend(&b[..]);
            // drop the body
            b.clear();
        }
        if end_of_stream {
            // This is the last chunk, we can process the data now
        }

        Ok(None)
    }
    ```

    Similarly we made sure we have captured the whole body iteratively.We consume the body since the buffer is directly tied to the response, we can buffer the response body in the `ctx` object.
    If the `end_of_stream` is true, we can process the buffered data and modify the response body as we see fit.

Helpful links:

- Examples: <https://github.com/cloudflare/pingora/tree/main/pingora-proxy/examples>
- Lifecycle of a request through Pingora: <https://github.com/cloudflare/pingora/blob/main/docs/user_guide/phase.md#pingora-proxy-phases-and-filters>
