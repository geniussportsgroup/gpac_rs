use gpac::FilterImplementation;
use std::sync::Arc;

use clap::Parser;

///////////////////////////////////////////////////////////////////////////////
// Filter callback functions

#[repr(C)]
struct PassthroughFilter {
    counter: u64,
    pids: Vec<PassthroughFilterPidPair>,
}

struct PassthroughFilterPidPair {
    input: Arc<gpac::FilterPid>,
    output: Arc<gpac::FilterPid>,
}

impl FilterImplementation<PassthroughFilter> for PassthroughFilter {
    fn initialize(_filter: &gpac::Filter, ctx: &mut PassthroughFilter) -> gpac::ErrorCode {
        ctx.counter = 0;
        gpac::ErrorCode::OK
    }

    fn finalize(_filter: &gpac::Filter, ctx: &mut PassthroughFilter) {
        println!("[passthrough] final counter value: {}", ctx.counter)
    }

    fn configure_pid(
        filter: &gpac::Filter,
        ctx: &mut PassthroughFilter,
        pid: Arc<gpac::FilterPid>,
        is_remove: bool,
    ) -> gpac::ErrorCode {
        println!("[passthrough] configure pid: {}", ctx.counter);

        if is_remove {
            let found = ctx.pids.iter().position(move |pair| pair.input == pid);
            if let Some(index) = found {
                let pair = ctx.pids.remove(index);
                println!(
                    "[passthrough] removed pid pair {0}",
                    pair.input.as_ref().name().unwrap_or_default()
                );
            }
        } else {
            println!(
                "[passthrough] configure pid: {}",
                pid.name().unwrap_or_default()
            );

            let mut output_pid = match filter.new_pid() {
                Some(pid) => pid,
                None => {
                    println!("[passthrough] error creating output pid");
                    return gpac::ErrorCode::IoErr;
                }
            };

            match pid.copy_properties(&mut output_pid) {
                Ok(_) => {}
                Err(_err) => {
                    println!("[passthrough] error copying pid properties");
                    return gpac::ErrorCode::IoErr;
                }
            }

            let pid_pair = PassthroughFilterPidPair {
                input: pid,
                output: Arc::new(output_pid),
            };

            ctx.pids.push(pid_pair);
        }

        gpac::ErrorCode::OK
    }

    fn process(_filter: &gpac::Filter, ctx: &mut PassthroughFilter) -> gpac::ErrorCode {
        for pid_pair in &ctx.pids {
            // untie the input/output pair
            let (input_pid, output_pid) = (&pid_pair.input, &pid_pair.output);

            // TODO: instead of returning an Option<Packet>, I could return a new
            //       enum that also includes EndOfStream.
            match input_pid.get_packet() {
                Some(packet) => {
                    let dts = packet.get_dts();

                    // create a packet clone assigned to the output pid
                    if let Some(output_packet) = packet.new_clone(output_pid) {
                        println!(
                            "[passthrough] from PID {} to PID {}, dts: {}",
                            input_pid.name().unwrap_or_default(),
                            output_pid.name().unwrap_or_default(),
                            dts
                        );

                        match output_packet.send() {
                            gpac::ErrorCode::OK => {}
                            err => {
                                println!("[passthrough] error sending packet: {}", err);
                            }
                        }

                        // finally, drop the packet
                        input_pid.drop_packet();
                    };
                }
                None => {
                    // check if EOS is reached, and if so, propagate to the output PID
                    if input_pid.eos_received() {
                        output_pid.set_eos();
                    }
                }
            }
        }

        ctx.counter += 1;

        gpac::ErrorCode::OK
    }
}

// end of filter callback functions
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// BOILER PLATE CODE
//
// Eventually, it can be generated automatically by deriving
// code in PassthroughFilter
//
// #[derive(GpacFilterRegisterImplementation)]
// #[repr(C)]
// struct PassthroughFilter{}

#[no_mangle]
pub extern "C" fn passthrough_initialize(
    filter_ptr: *mut gpac::bindings::GF_Filter,
) -> gpac::bindings::GF_Err {
    let filter = match gpac::Filter::from_ptr(filter_ptr) {
        Some(filter) => filter,
        None => {
            return gpac::bindings::GF_Err_GF_IO_ERR;
        }
    };

    let ctx = match filter.get_udta::<PassthroughFilter>() {
        Some(ctx) => ctx,
        None => {
            return gpac::bindings::GF_Err_GF_IO_ERR;
        }
    };

    let err = PassthroughFilter::initialize(&filter, ctx);
    err.into()
}

#[no_mangle]
pub extern "C" fn passthrough_finalize(filter_ptr: *mut gpac::bindings::GF_Filter) {
    let filter = match gpac::Filter::from_ptr(filter_ptr) {
        Some(filter) => filter,
        None => {
            return;
        }
    };

    let ctx = match filter.get_udta::<PassthroughFilter>() {
        Some(ctx) => ctx,
        None => {
            return;
        }
    };

    PassthroughFilter::finalize(&filter, ctx);
}

#[no_mangle]
pub extern "C" fn passthrough_configure_pid(
    filter_ptr: *mut gpac::bindings::GF_Filter,
    pid: *mut gpac::bindings::GF_FilterPid,
    is_remove: gpac::bindings::Bool,
) -> gpac::bindings::GF_Err {
    println!("passthrough_configure_pid");

    let filter = match gpac::Filter::from_ptr(filter_ptr) {
        Some(filter) => filter,
        None => {
            return gpac::bindings::GF_Err_GF_IO_ERR;
        }
    };

    let ctx = match filter.get_udta::<PassthroughFilter>() {
        Some(ctx) => ctx,
        None => {
            return gpac::bindings::GF_Err_GF_IO_ERR;
        }
    };

    let filter_pid = match gpac::FilterPid::from_ptr(pid) {
        Some(filter_pid) => filter_pid,
        None => {
            return gpac::bindings::GF_Err_GF_IO_ERR;
        }
    };

    let err = PassthroughFilter::configure_pid(
        &filter,
        ctx,
        Arc::new(filter_pid),
        is_remove == gpac::bindings::Bool_GF_TRUE,
    );

    err.into()
}

#[no_mangle]
pub extern "C" fn passthrough_process(
    filter_ptr: *mut gpac::bindings::GF_Filter,
) -> gpac::bindings::GF_Err {
    let filter = match gpac::Filter::from_ptr(filter_ptr) {
        Some(filter) => filter,
        None => {
            return gpac::bindings::GF_Err_GF_IO_ERR;
        }
    };

    let ctx = match filter.get_udta::<PassthroughFilter>() {
        Some(ctx) => ctx,
        None => {
            return gpac::bindings::GF_Err_GF_IO_ERR;
        }
    };

    let err = PassthroughFilter::process(&filter, ctx);
    err.into()
}

#[no_mangle]
pub extern "C" fn passthrough_get_filter_register() -> gpac::bindings::GF_FilterRegister {
    let caps = [
        gpac::FilterCapability::new_uint(
            gpac::CapabilityFlags::InputExcluded,
            gpac::BuiltInProperty::PidStreamType,
            gpac::bindings::GF_STREAM_FILE,
        ),
        gpac::FilterCapability::new_bool(
            gpac::CapabilityFlags::InputExcluded,
            gpac::BuiltInProperty::PidUnframed,
            true,
        ),
        gpac::FilterCapability::new_uint(
            gpac::CapabilityFlags::InputExcluded,
            gpac::BuiltInProperty::PidCodecid,
            gpac::bindings::GF_CodecID_GF_CODECID_NONE,
        ),
        gpac::FilterCapability::new_uint(
            gpac::CapabilityFlags::OutputExcluded,
            gpac::BuiltInProperty::PidStreamType,
            gpac::bindings::GF_STREAM_FILE,
        ),
        gpac::FilterCapability::new_uint(
            gpac::CapabilityFlags::OutputExcluded,
            gpac::BuiltInProperty::PidCodecid,
            gpac::bindings::GF_CodecID_GF_CODECID_NONE,
        ),
    ]
    .map(|it| it.into());

    gpac::bindings::GF_FilterRegister {
        name: std::ffi::CStr::from_bytes_with_nul(b"passthrough\0")
            .unwrap()
            .as_ptr(),
        private_size: std::mem::size_of::<PassthroughFilter>() as u32,
        max_extra_pids: 0,
        flags: 0,
        caps: caps.as_ptr(),
        nb_caps: caps.len() as u32,
        args: std::ptr::null(),
        process: Some(passthrough_process),
        configure_pid: Some(passthrough_configure_pid),
        initialize: Some(passthrough_initialize),
        finalize: Some(passthrough_finalize),
        update_arg: None,
        process_event: None,
        reconfigure_output: None,
        probe_url: None,
        probe_data: None,
        priority: 0,
        register_free: None,
        udta: std::ptr::null_mut(),
        use_alias: None,
        version: std::ffi::CStr::from_bytes_with_nul(b"0.0.1\0")
            .unwrap()
            .as_ptr(),
        description: std::ffi::CStr::from_bytes_with_nul(b"passthrough filter description\0")
            .unwrap()
            .as_ptr(),
        author: std::ffi::CStr::from_bytes_with_nul(b"Juan Adarve\0")
            .unwrap()
            .as_ptr(),
        help: std::ffi::CStr::from_bytes_with_nul(b"how to use the passthrough filter\0")
            .unwrap()
            .as_ptr(),
    }
}
// end of boiler plate code
///////////////////////////////////////////////////////////////////////////////

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

    let session = gpac::Session::new()?;

    let filter_register = gpac::FilterRegister::from_raw_binding(passthrough_get_filter_register())
        .ok_or(gpac::ErrorCode::NotSupported)?;

    session.add_filter_register(filter_register)?;

    for i in 0..session.get_filter_register_count()? {
        let filter_register = session.get_filter_register(i)?;
        println!("{:?}", filter_register);
    }

    ///////////////////////////////////////////////////////////////////////////
    // Create the pipeline

    let fin = session
        .load_filter(fin_spec.as_str())
        .expect("Error loading file input filter");

    let passthrough = session
        .load_filter("passthrough")
        .expect("Error loading passthrough filter");

    let fout = session
        .load_filter(fout_spec.as_str())
        .expect("Error loading file output filter");

    passthrough
        .set_source(&fin)
        .expect("Error setting passthrough source");
    fout.set_source(&passthrough)
        .expect("Error setting fout source.");

    // run the session
    session.run().expect("Error running session");

    println!("-----------------------------------------------------------------");
    session.print_all_connections("passthrough")?;
    println!("-----------------------------------------------------------------");
    session.print_connections()?;

    Ok(())
}
