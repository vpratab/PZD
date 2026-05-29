use marketplace_metering::{batch_meter_usage_payload, read_events_jsonl};
use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let product_code = args.next().ok_or_else(usage_error)?;
    let events_path = args.next().ok_or_else(usage_error)?;
    let pretty = args.any(|arg| arg == "--pretty");

    let events = read_events_jsonl(events_path)?;
    let payload = batch_meter_usage_payload(product_code, &events)?;
    if pretty {
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!("{}", serde_json::to_string(&payload)?);
    }
    Ok(())
}

fn usage_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "usage: pzdr-metering-payload <product-code> <events.jsonl> [--pretty]",
    )
}
