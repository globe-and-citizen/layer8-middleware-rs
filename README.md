# layer8-middleware-rs

## Getting Started

### Prerequisites

1. Install Node.js V22.x.x
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
