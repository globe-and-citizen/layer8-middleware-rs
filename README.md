# layer8-middleware-rs

We offer both a standalone software where the configuration file can be fed in through a CLI interface. And an npm package that can be used in app without the need for a standalone software, the only requirement is to have a module that is WebAssembly compatible.

These flavour can be found in the following directories:

1. [standalone](./middleware-standalone)
2. [npm package](./middleware-npm)

## Getting Started with the npm package

### Prerequisites

1. Install Node.js v22.x.x
2. Install Rust: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
3. Install wasm-pack: `cargo install wasm-pack`

### Running tests

The command below should set the node to v22.x.x and run the tests.

```bash
nvm use 22 && wasm-pack test --node --all-features
```

### Building

The command below will build the project locally. However, the project ships as an npm package, so you need not build it locally.

```bash
wasm-pack build --target nodejs --release
```

## Gotchas

1. The middleware expects request data to already be aggregated, call an aggregator middleware like `app.use(express.json({ limit: '100mb' }))` before registering this middleware.

## Getting Started with the standalone software

This is the complete standalone software for the layer8 middleware. It has two components:

1. The forward-proxy implementation that is involved in all proxing logic to the backend server.
2. The CLI interface that takes in the configuration file and starts the server.

### Prerequisites