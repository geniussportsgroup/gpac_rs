use gpac::FilterImplementation;
use gpac::{self, ErrorCode};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;

///////////////////////////////////////////////////////////////////////////////
// Filter callback functions

#[repr(C)]
struct TransportStreamSource {
    output_pid: gpac::FilterPid,
    reader: BufReader<File>,
}

impl FilterImplementation<TransportStreamSource> for TransportStreamSource {
    fn initialize(filter: &gpac::Filter, ctx: &mut TransportStreamSource) -> gpac::ErrorCode {
        println!("[ts_source] initialize");
        unsafe {
            let file = match File::open(INPUT_FILE.as_str()) {
                Ok(f) => f,
                Err(e) => {
                    println!("[ts_source] error reading input file: {}", e);
                    return gpac::ErrorCode::IoErr;
                }
            };

            // creates a buffered reader from the file
            ctx.reader = BufReader::new(file);
        }

        println!("[ts_source] creating output pid");
        match filter.new_pid() {
            Some(pid) => {
                _ = pid.set_name("ts_source");

                pid.set_property_u32(
                    gpac::BuiltInProperty::PidStreamType,
                    gpac::bindings::GF_STREAM_FILE,
                );
                pid.set_property_string(gpac::BuiltInProperty::PidFileExt, "ts");
                pid.set_property_string(gpac::BuiltInProperty::PidMime, "video/mpeg-2");

                ctx.output_pid = pid;
                gpac::ErrorCode::OK
            }
            None => {
                println!("[ts_source] error creating output pid");
                gpac::ErrorCode::OutOfMem
            }
        }
    }

    fn finalize(_filter: &gpac::Filter, _ctx: &mut TransportStreamSource) {
        println!("[ts_source] finalize")
    }

    fn configure_pid(
        _filter: &gpac::Filter,
        _ctx: &mut TransportStreamSource,
        pid: Arc<gpac::FilterPid>,
        is_remove: bool,
    ) -> gpac::ErrorCode {
        println!(
            "[ts_source] configure pid: {}, is_remove: {}",
            pid.name().unwrap(),
            is_remove
        );

        gpac::ErrorCode::OK
    }

    fn process(_filter: &gpac::Filter, ctx: &mut TransportStreamSource) -> gpac::ErrorCode {
        // read a Packetized Elementary Stream (PES) from the file
        let mut pes_buffer = vec![0u8; 188];

        match ctx.reader.read_exact(&mut pes_buffer) {
            Ok(_) => {
                // create a GPAC packet, set the data and send it.
                let packet = match ctx.output_pid.new_packet_from_data(&pes_buffer) {
                    Some(packet) => packet,
                    None => {
                        println!("No packet created");
                        return gpac::ErrorCode::OutOfMem;
                    }
                };

                packet.send()
            }
            Err(e) => {
                println!("[ts_source] error reading PES buffer: {}", e);
                ctx.output_pid.set_eos();
                gpac::ErrorCode::EOS
            }
        }
    }
}

// end of filter callback functions
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// BOILER PLATE CODE
//
// Eventually, it can be generated automatically by deriving
// code in TsSource
//
// #[derive(GpacFilterRegisterImplementation)]
// #[repr(C)]
// struct TsSource{}

#[no_mangle]
pub extern "C" fn transportstreamsource_initialize(
    filter_ptr: *mut gpac::bindings::GF_Filter,
) -> gpac::bindings::GF_Err {
    let filter = match gpac::Filter::from_ptr(filter_ptr) {
        Some(filter) => filter,
        None => {
            return gpac::bindings::GF_Err_GF_IO_ERR;
        }
    };

    let ctx = match filter.get_udta::<TransportStreamSource>() {
        Some(ctx) => ctx,
        None => {
            return gpac::bindings::GF_Err_GF_IO_ERR;
        }
    };

    let err = TransportStreamSource::initialize(&filter, ctx);
    err.into()
}

#[no_mangle]
pub extern "C" fn transportstreamsource_finalize(filter_ptr: *mut gpac::bindings::GF_Filter) {
    let filter = match gpac::Filter::from_ptr(filter_ptr) {
        Some(filter) => filter,
        None => {
            return;
        }
    };

    let ctx = match filter.get_udta::<TransportStreamSource>() {
        Some(ctx) => ctx,
        None => {
            return;
        }
    };

    TransportStreamSource::finalize(&filter, ctx);
}

#[no_mangle]
pub extern "C" fn transportstreamsource_configure_pid(
    filter_ptr: *mut gpac::bindings::GF_Filter,
    pid: *mut gpac::bindings::GF_FilterPid,
    is_remove: gpac::bindings::Bool,
) -> gpac::bindings::GF_Err {
    println!("transportstreamsource_configure_pid");

    let filter = match gpac::Filter::from_ptr(filter_ptr) {
        Some(filter) => filter,
        None => {
            return gpac::bindings::GF_Err_GF_IO_ERR;
        }
    };

    let ctx = match filter.get_udta::<TransportStreamSource>() {
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

    let err = TransportStreamSource::configure_pid(
        &filter,
        ctx,
        Arc::new(filter_pid),
        is_remove == gpac::bindings::Bool_GF_TRUE,
    );

    err.into()
}

#[no_mangle]
pub extern "C" fn transportstreamsource_process(
    filter_ptr: *mut gpac::bindings::GF_Filter,
) -> gpac::bindings::GF_Err {
    let filter = match gpac::Filter::from_ptr(filter_ptr) {
        Some(filter) => filter,
        None => {
            return gpac::bindings::GF_Err_GF_IO_ERR;
        }
    };

    let ctx = match filter.get_udta::<TransportStreamSource>() {
        Some(ctx) => ctx,
        None => {
            return gpac::bindings::GF_Err_GF_IO_ERR;
        }
    };

    let err = TransportStreamSource::process(&filter, ctx);
    err.into()
}

#[no_mangle]
pub extern "C" fn transportstreamsource_process_event(
    _filter: *mut gpac::bindings::GF_Filter,
    _evt: *const gpac::bindings::GF_FilterEvent,
) -> gpac::bindings::Bool {
    println!("transportstreamsource_process_event");

    gpac::bindings::Bool_GF_FALSE
}

#[no_mangle]
pub extern "C" fn transportstreamsource_reconfigure_output(
    _filter: *mut gpac::bindings::GF_Filter,
    _pid: *mut gpac::bindings::GF_FilterPid,
) -> gpac::bindings::GF_Err {
    println!("transportstreamsource_reconfigure_output");

    gpac::bindings::GF_Err_GF_OK
}

/// # Safety
///
/// Both url and mime must be valid C strings
#[no_mangle]
pub unsafe extern "C" fn transportstreamsource_probe_url(
    url: *const ::std::os::raw::c_char,
    mime: *const ::std::os::raw::c_char,
) -> gpac::bindings::GF_FilterProbeScore {
    unsafe {
        println!(
            "transportstreamsource_probe_url: URL: {} MIME: {}",
            std::ffi::CStr::from_ptr(url).to_str().unwrap(),
            std::ffi::CStr::from_ptr(mime).to_str().unwrap()
        );
    }
    gpac::bindings::GF_FilterProbeScore_GF_FPROBE_SUPPORTED
}

#[no_mangle]
pub extern "C" fn transportstreamsource_get_filter_register() -> gpac::bindings::GF_FilterRegister {
    // These caps are the same as the ones defined for the MPEG-TS muxer in GPAC.
    // I expect to fool the rest of the graph saying this custom filter
    // produces TS segments (which is true)
    let caps = [
        gpac::FilterCapability::new_uint(
            gpac::CapabilityFlags::OutputStatic,
            gpac::BuiltInProperty::PidStreamType,
            gpac::bindings::GF_STREAM_FILE,
        ),
        // NOTE: enabling these two capabilities makes the filter to no longer appear as a source
        gpac::FilterCapability::new_string(
            gpac::CapabilityFlags::OutputStatic,
            gpac::BuiltInProperty::PidFileExt,
            "ts", // taken from M2TS_FILE_EXTS at mux_ts.c
        ),
        gpac::FilterCapability::new_string(
            gpac::CapabilityFlags::OutputStatic,
            gpac::BuiltInProperty::PidMime,
            "video/mpeg-2", // taken from M2TS_MIMES at mux_ts.c
        ),
        gpac::FilterCapability::new_zeroed(),
    ]
    .map(|it| it.into());

    gpac::bindings::GF_FilterRegister {
        name: std::ffi::CStr::from_bytes_with_nul(b"tssource\0")
            .unwrap()
            .as_ptr(),
        private_size: std::mem::size_of::<TransportStreamSource>() as u32,
        max_extra_pids: 0,
        flags: 0,
        caps: caps.as_ptr(),
        nb_caps: caps.len() as u32,
        args: std::ptr::null(),
        process: Some(transportstreamsource_process),
        configure_pid: Some(transportstreamsource_configure_pid),
        initialize: Some(transportstreamsource_initialize),
        finalize: Some(transportstreamsource_finalize),
        update_arg: None,
        process_event: Some(transportstreamsource_process_event),
        reconfigure_output: Some(transportstreamsource_reconfigure_output),
        probe_url: Some(transportstreamsource_probe_url),
        probe_data: None,
        priority: 0,
        register_free: None,
        udta: std::ptr::null_mut(),
        use_alias: None,
        version: std::ffi::CStr::from_bytes_with_nul(b"0.0.1\0")
            .unwrap()
            .as_ptr(),
        description: std::ffi::CStr::from_bytes_with_nul(b"tssource filter description\0")
            .unwrap()
            .as_ptr(),
        author: std::ffi::CStr::from_bytes_with_nul(b"Juan Adarve\0")
            .unwrap()
            .as_ptr(),
        help: std::ffi::CStr::from_bytes_with_nul(b"how to use the tssource filter\0")
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

static mut INPUT_FILE: String = String::new();

fn main() -> Result<(), ErrorCode> {
    // parse the command line arguments
    let args = CliArgs::parse();
    let fin_spec = "tssource".to_string();

    let out_path = PathBuf::from(args.output_file);
    let base_dir = out_path
        .canonicalize()
        .expect("Error creating canonical path for output");

    if !base_dir.is_dir() {
        println!("Expecting a directory output, got a file, aborting");
        return Err(gpac::ErrorCode::BadParam);
    }

    let manifest_path = base_dir
        .join("manifest.mpd")
        .to_str()
        .map(String::from)
        .expect("");

    let segment_path = base_dir
        .join("P1V2_dashinit.mp4")
        .to_str()
        .map(String::from)
        .expect("");

    let manifest_spec = format!("fout:dst={}", manifest_path);
    let segment_spec = format!(
        "fout:dst={}:gfopt:frag:xps_inband=no:psshs=moov:mime=video/mp4:use_rel",
        segment_path
    );

    unsafe {
        INPUT_FILE = args.input_file;
    }

    println!("FOUT spec: {}", manifest_spec);

    let session = gpac::Session::new().expect("Unable to create session");
    // session.enable_debug_output();

    let filter_register =
        gpac::FilterRegister::from_raw_binding(transportstreamsource_get_filter_register())
            .unwrap();

    session.add_filter_register(filter_register)?;

    ///////////////////////////////////////////////////////////////////////////
    // Create the pipeline

    let tssource = session
        .load_filter(fin_spec.as_str())
        .expect("Error loading file input filter");

    let m2tsdmx = session
        .load_filter("m2tsdmx")
        .expect("Error loading m2tsdmx");

    let rfnalu = session.load_filter("rfnalu").expect("Error loading rfnalu");

    let dasher = session
        .load_filter("dasher")
        .expect("Error loading file output filter");

    let manifest_fout = session
        .load_filter(manifest_spec.as_str())
        .expect("Error loading fout");

    let segment_fout = session
        .load_filter(segment_spec.as_str())
        .expect("Error loading fout for segments");

    /*
    fin (src=test.ts) (idx=1)
    -(PID test.ts) m2tsdmx (dyn_idx=3)
    --(PID P1V2) rfnalu (dyn_idx=4)
    ---(PID P1V2) dasher (dyn_idx=5)
    ----(PID manifest_mpd) fout (dst=out_gpac/manifest.mpd) (idx=2)
    ----(PID P1V2)         mp4mx (dyn_idx=7)
    -----(PID P1V2) fout (dst=out_gpac/test_dashinit.mp4:gfopt:frag:xps_inband=no:psshs=moov:mime=video/mp4) (idx=6)
     */

    m2tsdmx
        .set_source(&tssource)
        .expect("Error setting m2tsdmx source");

    rfnalu
        .set_source(&m2tsdmx)
        .expect("Error setting rfnalu source");

    dasher
        .set_source(&rfnalu)
        .expect("Error setting dasher source");

    manifest_fout
        .set_source(&dasher)
        .expect("Error setting manifest_fout source");

    // I need this so that the segments are written at the correct folder destination
    segment_fout
        .set_source(&dasher)
        .expect("Error setting segment_out source");

    // run the session
    session.run()?;

    println!("-----------------------------------------------------------------");
    session.print_all_connections("tssource")?;
    println!();
    session.print_all_connections("m2tsmx")?;
    println!();
    session.print_all_connections("m2tsdmx")?;
    println!("-----------------------------------------------------------------");
    println!("IS SOURCE: {}", tssource.is_source());
    println!("IS SINK: {}", tssource.is_sink());
    println!("-----------------------------------------------------------------");
    session.print_connections()?;

    Ok(())
}
