use clap::Parser;

/// Simple cli to forward http requests to using the forward-proxy crate
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Port to forward the requests to after processing
    #[arg(short, long)]
    port: u16,
}

fn main() {
    let args = Args::parse();
    if args.port.eq(&0) {
        println!("Port cannot be 0");
    }
}
