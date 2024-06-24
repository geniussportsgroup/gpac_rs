use std::env;
use std::path::PathBuf;

fn main() {
    // list of allowed types and functions to generate bindings for
    let allowed_types = [
        "GF_FilterSession",
        "GF_FilterRegister",
        "GF_FSRegisterFlags",
        "GS_Err",
        "GF_Filter",
        "GF_FilterPid",
        "GF_CodecID",
    ];
    let allowed_functions = [
        // GF_Err
        "gf_error_to_string",
        // GF_FilterSession
        "gf_fs_add_filter_register",
        "gf_fs_del",
        "gf_fs_filters_registers_count",
        "gf_fs_get_filter_register",
        "gf_fs_load_destination",
        "gf_fs_load_filter",
        "gf_fs_load_source",
        "gf_fs_new",
        "gf_fs_new_defaults",
        "gf_fs_new_filter",
        "gf_fs_print_connections",
        "gf_fs_print_all_connections",
        "gf_fs_print_debug_info",
        "gf_fs_run",
        // GF_Filter,
        "gf_filter_get_arg",
        "gf_filter_get_udta",
        "gf_filter_is_sink",
        "gf_filter_is_source",
        "gf_filter_pid_new",
        "gf_filter_pid_raw_new",
        "gf_filter_push_caps",
        "gf_filter_get_caps",
        "gf_filter_reconnect_output",
        "gf_filter_set_source",
        // GF_FilterPid
        "gf_filter_pid_copy_properties",
        "gf_filter_pid_drop_packet",
        "gf_filter_pid_eos_received",
        "gf_filter_pid_get_name",
        "gf_filter_pid_get_packet",
        "gf_filter_pid_set_eos",
        "gf_filter_pid_set_name",
        "gf_filter_pid_set_property",
        // GF_FilterPacket
        "gf_filter_pck_get_data",
        "gf_filter_pck_get_dts",
        "gf_filter_pck_new_alloc",
        "gf_filter_pck_new_clone",
        "gf_filter_pck_send",
        // GF_Property
        "gf_props_reset_single",
    ];
    let allowed_vars = [
        "GF_CAPFLAG_IN_BUNDLE", // flags for filter capabilities. Bindgen wraps all of them.
        "GF_PROP_PID_ID",       // Built-in property types.
        "GF_STREAM_UNKNOWN",    // Media stream types.
    ];

    // Tell cargo to look for shared libraries in the specified directory
    // println!("cargo:rustc-link-search=/path/to/lib");

    // Tell cargo to tell rustc to link the system gpac shared library.
    println!("cargo:rustc-link-lib=gpac");
    println!("cargo:rustc-link-lib=nghttp2");

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=src/wrapper.hpp");

    // The bindgen::Builder is the main entry point to bindgen, and lets you
    // build up options for the resulting bindings.
    let mut builder = bindgen::Builder::default()
        .header("src/wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .layout_tests(true);

    // include all allowed types and functions
    for t in allowed_types {
        builder = builder.allowlist_type(t);
    }

    for t in allowed_functions {
        builder = builder.allowlist_function(t);
    }

    for t in allowed_vars {
        builder = builder.allowlist_var(t);
    }

    // generate the bindings
    let bindings = builder.generate().expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
