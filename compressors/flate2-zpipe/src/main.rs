use clap::Parser;
use flate2::bufread::{DeflateDecoder, DeflateEncoder};
use flate2::Compression;
use std::io;
use std::io::BufReader;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value_t = false)]
    decompress: bool,

    #[arg(short, long, default_value_t = 6)]
    level: u32,
}

fn main() {
    let args = Args::parse();

    let stdin = BufReader::new(io::stdin());
    let mut stdout = io::stdout().lock();

    if args.decompress {
        let mut inflater = DeflateDecoder::new(stdin);
        io::copy(&mut inflater, &mut stdout).unwrap();
    } else {
        let mut deflater = DeflateEncoder::new(stdin, Compression::new(args.level));
        io::copy(&mut deflater, &mut stdout).unwrap();
    }
}
