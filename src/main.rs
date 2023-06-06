use clap::Parser;
use rust_herpaderping::herpaderping;
use simple_logger::SimpleLogger;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct HerpaderpingCli {
    source_filename: String,
    target_filename: String,
    cover_filename: Option<String>,
}

fn main() {
    SimpleLogger::new().init().unwrap();
    let cli = HerpaderpingCli::parse();

    unsafe {
        herpaderping(
            &cli.source_filename,
            &cli.target_filename,
            &cli.cover_filename,
        );
    }
}
