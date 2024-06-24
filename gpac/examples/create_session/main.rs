fn main() -> Result<(), gpac::ErrorCode> {
    let session = gpac::Session::new()?;

    // TODO: Use iterators to traverse the filter registry
    for i in 0..session.get_filter_register_count()? {
        let filter_register = session.get_filter_register(i)?;

        println!("{:?}", filter_register);
    }

    Ok(())
}
