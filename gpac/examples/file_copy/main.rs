use clap::Parser;

#[derive(Parser)]
struct CliArgs {
    #[arg(long = "input-file")]
    input_file: String,

    #[arg(long = "output-file")]
    output_file: String,
}

fn main() -> Result<(), gpac::ErrorCode> {
    // parse the command line arguments
    let args = CliArgs::parse();
    let fin_spec = format!("fin:src={}", args.input_file);
    let fout_spec = format!("fout:dst={}", args.output_file);

    // create GPAC session
    let session = gpac::Session::new()?;

    let fin = session.load_filter(fin_spec.as_str())?;
    let fout = session.load_filter(fout_spec.as_str())?;

    fout.set_source(&fin)?;

    // run the session
    session.run()?;

    Ok(())
}
