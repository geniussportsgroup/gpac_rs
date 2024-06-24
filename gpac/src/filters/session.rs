use std::borrow::Borrow;
use std::cell::Cell;
use std::pin::Pin;
use std::sync::Mutex;

use crate::bindings;
use crate::filters::{error, filter, filter_register};

pub struct Session {
    state: Mutex<SessionState>,
}

struct SessionState {
    ptr: std::ptr::NonNull<bindings::GF_FilterSession>,

    // Stores references to the custom filter registers added by the user
    // It needs to be a Cell as I need to mutate the vector from the add_filter_register method
    custom_filter_registers: Cell<Vec<Pin<Box<filter_register::FilterRegister>>>>,
}

///////////////////////////////////////////////////////////////////////////////
// Trait implementations

unsafe impl Send for Session {}
unsafe impl Sync for Session {}

impl Drop for Session {
    fn drop(&mut self) {
        println!("gpac::Session::drop");

        match self.state.lock() {
            Ok(state) => unsafe {
                bindings::gf_fs_del(state.ptr.as_ptr());
            },
            Err(err) => {
                println!("gpac::Session::drop: failed to lock the state: {:?}", err);
            }
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

// mutex for creating Session instances using Session::new()
static NEW_SESSION_MUTEX: Mutex<()> = Mutex::new(());

impl Session {
    pub fn new() -> Result<Session, error::ErrorCode> {
        let _guard = NEW_SESSION_MUTEX
            .lock()
            .map_err(|_| error::ErrorCode::RustSyncError)?;

        let ptr = unsafe {
            std::ptr::NonNull::new(bindings::gf_fs_new_defaults(0))
                .ok_or(error::ErrorCode::OutOfMem)?

            // schedulers: 1, 4
            // std::ptr::NonNull::new(bindings::gf_fs_new(8, 2u32, 0u32, std::ptr::null()))
            //     .ok_or(error::ErrorCode::OutOfMem)?
        };

        let state = SessionState {
            ptr,
            custom_filter_registers: Cell::new(Vec::new()),
        };

        Ok(Session {
            state: Mutex::new(state),
        })
    }

    pub fn enable_debug_output(&self) -> Result<(), error::ErrorCode> {
        let state = self
            .state
            .lock()
            .map_err(|_| error::ErrorCode::RustSyncError)?;

        unsafe {
            let flags = bindings::GF_SessionDebugFlag_GF_FS_DEBUG_CONTINUOUS
                | bindings::GF_SessionDebugFlag_GF_FS_DEBUG_ALL;

            bindings::gf_fs_print_debug_info(state.ptr.as_ptr(), flags);
        };

        Ok(())
    }

    pub fn print_connections(&self) -> Result<(), error::ErrorCode> {
        let state = self
            .state
            .lock()
            .map_err(|_| error::ErrorCode::RustSyncError)?;

        unsafe {
            bindings::gf_fs_print_connections(state.ptr.as_ptr());
        };

        Ok(())
    }

    pub fn print_all_connections(&self, filter_name: &str) -> Result<(), error::ErrorCode> {
        let state = self
            .state
            .lock()
            .map_err(|_| error::ErrorCode::RustSyncError)?;

        unsafe {
            let c_filter_name = std::ffi::CString::new(filter_name).unwrap();
            bindings::gf_fs_print_all_connections(
                state.ptr.as_ptr(),
                c_filter_name.as_ptr().cast_mut(),
                None,
            );
        };

        Ok(())
    }

    pub fn add_filter_register(
        &self,
        filter_register: filter_register::FilterRegister,
    ) -> Result<(), error::ErrorCode> {
        let state = self
            .state
            .lock()
            .map_err(|_| error::ErrorCode::RustSyncError)?;

        unsafe {
            let filter_register_box = Box::pin(filter_register);

            bindings::gf_fs_add_filter_register(
                state.ptr.as_ptr(),
                &filter_register_box.borrow().binding as *const bindings::GF_FilterRegister,
            );

            let mut new_registers = state.custom_filter_registers.take();
            new_registers.push(filter_register_box);
            state.custom_filter_registers.replace(new_registers);
        }

        Ok(())
    }

    pub fn get_filter_register_count(&self) -> Result<usize, error::ErrorCode> {
        let state = self
            .state
            .lock()
            .map_err(|_| error::ErrorCode::RustSyncError)?;

        unsafe { Ok(bindings::gf_fs_filters_registers_count(state.ptr.as_ptr()) as usize) }
    }

    pub fn get_filter_register(
        &self,
        i: usize,
    ) -> Result<filter_register::FilterRegister, error::ErrorCode> {
        let state = self
            .state
            .lock()
            .map_err(|_| error::ErrorCode::RustSyncError)?;
        unsafe {
            let filter_register_ptr =
                bindings::gf_fs_get_filter_register(state.ptr.as_ptr(), i as u32);
            filter_register::FilterRegister::from_ptr(filter_register_ptr)
                .ok_or(error::ErrorCode::BadParam)
        }
    }

    pub fn load_filter(&self, spec: &str) -> Result<filter::Filter, error::ErrorCode> {
        let state = self
            .state
            .lock()
            .map_err(|_| error::ErrorCode::RustSyncError)?;

        unsafe {
            let mut gf_err: bindings::GF_Err = bindings::GF_Err_GF_OK;

            // unwrapping here should be safe as we are passing a valid &str reference
            let spec_cstr = std::ffi::CString::new(spec).unwrap();

            let gf_filter_ptr = bindings::gf_fs_load_filter(
                state.ptr.as_ptr(),
                spec_cstr.as_ptr(),
                &mut gf_err as *mut bindings::GF_Err,
            );

            if gf_err != bindings::GF_Err_GF_OK {
                return Err(error::ErrorCode::from(gf_err));
            }

            filter::Filter::from_ptr(gf_filter_ptr).ok_or(error::ErrorCode::FilterNotFound)
        }
    }

    pub fn load_filter_destination(
        &self,
        url: &str,
        args: &str,
    ) -> Result<filter::Filter, error::ErrorCode> {
        let state = self
            .state
            .lock()
            .map_err(|_| error::ErrorCode::RustSyncError)?;

        unsafe {
            let mut gf_err: bindings::GF_Err = bindings::GF_Err_GF_OK;

            // unwrapping here should be safe as we are passing a valid &str reference
            let url_cstr = std::ffi::CString::new(url).unwrap();
            let args_cstr = std::ffi::CString::new(args).unwrap();

            let gf_filter_ptr = bindings::gf_fs_load_destination(
                state.ptr.as_ptr(),
                url_cstr.as_ptr(),
                args_cstr.as_ptr(),
                std::ptr::null(),
                &mut gf_err as *mut bindings::GF_Err,
            );

            if gf_err != bindings::GF_Err_GF_OK {
                return Err(error::ErrorCode::from(gf_err));
            }

            filter::Filter::from_ptr(gf_filter_ptr).ok_or(error::ErrorCode::FilterNotFound)
        }
    }

    pub fn load_filter_source(
        &self,
        url: &str,
        args: &str,
    ) -> Result<filter::Filter, error::ErrorCode> {
        let state = self
            .state
            .lock()
            .map_err(|_| error::ErrorCode::RustSyncError)?;

        unsafe {
            let mut gf_err: bindings::GF_Err = bindings::GF_Err_GF_OK;

            // unwrapping here should be safe as we are passing a valid &str reference
            let url_cstr = std::ffi::CString::new(url).unwrap();
            let args_cstr = std::ffi::CString::new(args).unwrap();

            let gf_filter_ptr = bindings::gf_fs_load_source(
                state.ptr.as_ptr(),
                url_cstr.as_ptr(),
                args_cstr.as_ptr(),
                std::ptr::null(),
                &mut gf_err as *mut bindings::GF_Err,
            );

            if gf_err != bindings::GF_Err_GF_OK {
                return Err(error::ErrorCode::from(gf_err));
            }

            filter::Filter::from_ptr(gf_filter_ptr).ok_or(error::ErrorCode::FilterNotFound)
        }
    }

    pub fn create_custom_filter(&self, name: &str) -> Result<filter::Filter, error::ErrorCode> {
        let state = self
            .state
            .lock()
            .map_err(|_| error::ErrorCode::RustSyncError)?;

        let c_name = std::ffi::CString::new(name).unwrap();

        let mut gf_err: bindings::GF_Err = bindings::GF_Err_GF_OK;

        let filter_ptr = unsafe {
            bindings::gf_fs_new_filter(
                state.ptr.as_ptr(),
                c_name.as_ptr(),
                bindings::GF_FSRegisterFlags_GF_FS_REG_MAIN_THREAD,
                &mut gf_err as *mut bindings::GF_Err,
            )
        };

        match error::ErrorCode::from(gf_err) {
            error::ErrorCode::OK => {
                filter::Filter::from_ptr(filter_ptr).map_or(Err(error::ErrorCode::OutOfMem), Ok)
            }
            err => Err(err),
        }
    }

    pub fn run(&self) -> Result<error::ErrorCode, error::ErrorCode> {
        let state = self
            .state
            .lock()
            .map_err(|_| error::ErrorCode::RustSyncError)?;

        unsafe {
            let gf_err = bindings::gf_fs_run(state.ptr.as_ptr());
            Ok(error::ErrorCode::from(gf_err))
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::bindings;
    use crate::filters::filter_register;
    use crate::ErrorCode;
    use crate::Session;

    #[test]
    fn test_create_and_destroy_session() -> Result<(), ErrorCode> {
        ///////////////////////////////////////////////////////////////////////
        // Given session object created within a scope
        // When the scope is completed
        // Then the session object should be deleted and the underlying
        // gpac session object deleted.
        {
            let _session = Session::new()?;
        }

        Ok(())
    }

    #[test]
    fn test_there_should_be_filters_in_session() -> Result<(), ErrorCode> {
        ///////////////////////////////////////////////////////////////////////
        // Given session object
        let session = Session::new()?;

        ///////////////////////////////////////////////////////////////////////
        // When obtaining the number of available filters
        let available_filters = session.get_filter_register_count()?;

        ///////////////////////////////////////////////////////////////////////
        // Then the number should be greater than zero
        assert!(available_filters > 0);
        Ok(())
    }

    #[test]
    fn test_getting_filter_register_in_bounds() -> Result<(), ErrorCode> {
        ///////////////////////////////////////////////////////////////////////
        // Given session object and the available filter count
        let session = Session::new()?;

        ///////////////////////////////////////////////////////////////////////
        // When obtaining the filter register for all available filters
        let filter_register_count = session.get_filter_register_count()?;
        for i in 0..filter_register_count {
            ///////////////////////////////////////////////////////////////////
            // Then the result should be Ok
            let _r = session.get_filter_register(i)?;
        }

        Ok(())
    }

    #[test]
    fn test_getting_filter_register_out_of_bounds() -> Result<(), ErrorCode> {
        ///////////////////////////////////////////////////////////////////////
        // Given session object and the available filter count
        let session = Session::new()?;

        ///////////////////////////////////////////////////////////////////////
        // When obtaining the filter register outside of the boundaries
        let filter_register_count = session.get_filter_register_count()?;
        let r = session.get_filter_register(filter_register_count);

        ///////////////////////////////////////////////////////////////////////
        // Then the result should be an error
        assert!(r.is_err_and(|err| { err == ErrorCode::BadParam }));
        Ok(())
    }

    #[test]
    fn test_load_filters() -> Result<(), ErrorCode> {
        ///////////////////////////////////////////////////////////////////////
        // Given session object and a list of filters to load
        let session = Session::new()?;

        let filters_to_load = ["probe", "inspect", "reframer"];

        for filter_name in filters_to_load {
            ///////////////////////////////////////////////////////////////////
            // When creating a filter from the filter name
            // Then the result should be ok
            let _filter_result = session.load_filter(filter_name)?;
        }

        Ok(())
    }

    #[test]
    fn test_load_filter_bad_param() -> Result<(), ErrorCode> {
        ///////////////////////////////////////////////////////////////////////
        // Given session object
        let session = Session::new()?;

        ///////////////////////////////////////////////////////////////////////
        // When creating a "fin" filter without its src parameter
        let filter_result = session.load_filter("fin");

        ///////////////////////////////////////////////////////////////////////
        // Then the result should be an error of specific error code.
        assert!(filter_result.is_err_and(|err| err == ErrorCode::BadParam));

        Ok(())
    }

    #[test]
    fn test_load_filter_unknown_filter() -> Result<(), ErrorCode> {
        ///////////////////////////////////////////////////////////////////////
        // Given session object
        let session = Session::new()?;

        ///////////////////////////////////////////////////////////////////////
        // When creating a "unknown_filter" filter
        let filter_result = session.load_filter("unknown_filter");

        ///////////////////////////////////////////////////////////////////////
        // Then the result should be an error of specific error code.
        assert!(filter_result.is_err_and(|err| err == ErrorCode::FilterNotFound));

        Ok(())
    }

    #[test]
    fn test_load_filter_empty_filter_name() -> Result<(), ErrorCode> {
        ///////////////////////////////////////////////////////////////////////
        // Given session object
        let session = Session::new()?;

        ///////////////////////////////////////////////////////////////////////
        // When creating a filter with an empty name
        let filter_result = session.load_filter("");

        ///////////////////////////////////////////////////////////////////////
        // Then the result should be an error of specific error code.
        assert!(filter_result.is_err_and(|err| err == ErrorCode::FilterNotFound));

        Ok(())
    }

    #[test]
    fn test_create_custom_filter() -> Result<(), ErrorCode> {
        ///////////////////////////////////////////////////////////////////////
        // Given session object
        let session = Session::new()?;

        ///////////////////////////////////////////////////////////////////////
        // When creating a custom filter with a given name
        // Then the result should be ok
        let _custom_filter = session.create_custom_filter("my_filter")?;

        Ok(())
    }

    #[test]
    fn test_enumerate_filters_in_another_thread() -> Result<(), ErrorCode> {
        ///////////////////////////////////////////////////////////////////////
        // Given session object created in this thread
        let session = Session::new()?;

        ///////////////////////////////////////////////////////////////////////
        // When enumerating the available filters from another thread
        let thread_handler = std::thread::spawn(move || -> Result<(), ErrorCode> {
            let filter_register_count = session.get_filter_register_count()?;
            assert!(
                filter_register_count > 0,
                "There must be filter registers available, got 0"
            );

            let filter_register_count = session.get_filter_register_count()?;
            for i in 0..filter_register_count {
                let _filter_register = session.get_filter_register(i)?;
                // assert!(filter_register.is_some(), "got an empty filter register");
            }

            Ok(())
        });

        assert!(
            thread_handler.join().is_ok(),
            "Auxiliar thread not joined successfully"
        );

        Ok(())
    }

    #[test]
    fn test_add_filter_register() -> Result<(), String> {
        ///////////////////////////////////////////////////////////////////////
        // Given a session object
        let session = Session::new().map_err(|err_code| err_code.to_string())?;

        ///////////////////////////////////////////////////////////////////////
        // When adding a new filter register into the session in another scope
        register_mydummysource(&session)?;

        ///////////////////////////////////////////////////////////////////////
        // Then, when scanning the available filter register, the new filter should be there
        let mut found = false;
        let filter_register_count = session
            .get_filter_register_count()
            .map_err(|e| e.to_string())?;
        for i in 0..filter_register_count {
            let filter_register = session.get_filter_register(i).map_err(|e| e.to_string())?;

            let filter_name = filter_register
                .name()
                .map_err(|err| format!("FilterRegister name error: {}", err))?;
            println!("{} : {}", i, filter_name);
            if filter_name == "mydummysource" {
                found = true;
                // keep scanning and consuming all the filter registers regardless
            }
        }

        assert!(found, "FilterRegister not found");

        Ok(())
    }

    fn register_mydummysource(session: &Session) -> Result<(), String> {
        // the binding will be dropped as soon as the scope is completed
        let filter_register_binding = bindings::GF_FilterRegister {
            name: std::ffi::CStr::from_bytes_with_nul(b"mydummysource\0")
                .unwrap()
                .as_ptr(),
            private_size: 0,
            max_extra_pids: 0,
            flags: 0,
            caps: std::ptr::null(),
            nb_caps: 0_u32,
            args: std::ptr::null(),
            process: Some(mydummysource_process),
            configure_pid: Some(mydummysource_configure_pid),
            initialize: Some(mydummysource_initialize),
            finalize: Some(mydummysource_finalize),
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
            description: std::ffi::CStr::from_bytes_with_nul(b"mydummysource filter description\0")
                .unwrap()
                .as_ptr(),
            author: std::ffi::CStr::from_bytes_with_nul(b"Juan Adarve\0")
                .unwrap()
                .as_ptr(),
            help: std::ffi::CStr::from_bytes_with_nul(b"how to use the mydummysource filter\0")
                .unwrap()
                .as_ptr(),
        };

        let filter_register =
            filter_register::FilterRegister::from_raw_binding(filter_register_binding)
                .ok_or("FilterRegister creation failed")?;

        session
            .add_filter_register(filter_register)
            .map_err(|err| err.to_string())
    }

    /////////////////////////////////////
    // Dummy filter implementations
    #[no_mangle]
    pub extern "C" fn mydummysource_initialize(
        _filter_ptr: *mut bindings::GF_Filter,
    ) -> bindings::GF_Err {
        ErrorCode::OK.into()
    }

    #[no_mangle]
    pub extern "C" fn mydummysource_finalize(_filter_ptr: *mut bindings::GF_Filter) {}

    #[no_mangle]
    pub extern "C" fn mydummysource_configure_pid(
        _filter_ptr: *mut bindings::GF_Filter,
        _pid: *mut bindings::GF_FilterPid,
        _is_remove: bindings::Bool,
    ) -> bindings::GF_Err {
        ErrorCode::OK.into()
    }

    #[no_mangle]
    pub extern "C" fn mydummysource_process(
        _filter_ptr: *mut bindings::GF_Filter,
    ) -> bindings::GF_Err {
        ErrorCode::OK.into()
    }
    /////////////////////////////////////
}
