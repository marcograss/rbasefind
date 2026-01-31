use clap::Parser;
use rbasefind::Config;
use std::process;

fn main() {
    env_logger::init();
    let config = Config::parse();

    if let Err(e) = rbasefind::run(&config) {
        eprintln!("Application error: {e}");
        process::exit(1);
    }
}
