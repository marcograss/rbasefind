use rbasefind::Config;
use std::process;

fn main() {
    env_logger::init();
    let config = Config::new().unwrap_or_else(|err| {
        eprintln!("Problem parsing arguments: {err}");
        process::exit(1);
    });

    if let Err(e) = rbasefind::run(config) {
        eprintln!("Application error: {e}");
        process::exit(1);
    }
}
