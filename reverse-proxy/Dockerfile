FROM ubuntu:20.04

RUN apt-get update && apt-get install -y curl tar

# Getting a pre-built layer8-reverse-proxy
RUN curl "https://github.com/globe-and-citizen/layer8-middleware-rs/releases/download/v0.1.24/layer8-middleware-rs_v0.1.24_x86_64-unknown-linux-musl.tar.gz" \
    --output "./layer8-reverse-proxy.tar.gz"
RUN tar xzf layer8-reverse-proxy.tar.gz

FROM scratch

COPY --from=0 /layer8-reverse-proxy /layer8-reverse-proxy

CMD ["./layer8-reverse-proxy"]
