use crate::filters::error;
use crate::{bindings, str_util, FilterCapability, FilterPid};

pub trait FilterImplementation<T> {
    fn initialize(filter: &Filter, ctx: &mut T) -> error::ErrorCode;

    fn finalize(filter: &Filter, ctx: &mut T);

    fn configure_pid(
        filter: &Filter,
        ctx: &mut T,
        pid: std::sync::Arc<FilterPid>,
        is_remove: bool,
    ) -> error::ErrorCode;

    fn process(filter: &Filter, ctx: &mut T) -> error::ErrorCode;
}

pub struct Filter {
    // a not-null pointer to the underlying filter
    pub(crate) ptr: *mut bindings::GF_Filter,
}

///////////////////////////////////////////////////////////////////////////////
// Trait implementations
unsafe impl Send for crate::Filter {}
unsafe impl Sync for crate::Filter {}

///////////////////////////////////////////////////////////////////////////////
impl Filter {
    pub fn from_ptr(ptr: *mut bindings::GF_Filter) -> Option<Self> {
        match ptr.is_null() {
            true => None,
            false => Some(Filter { ptr }),
        }
    }

    pub fn set_source(&self, source: &Filter) -> Result<(), error::ErrorCode> {
        unsafe {
            let gf_err = bindings::gf_filter_set_source(self.ptr, source.ptr, std::ptr::null());

            match error::ErrorCode::from(gf_err) {
                error::ErrorCode::OK => Ok(()),
                err => Err(err),
            }
        }
    }

    pub fn push_caps(&self, caps: &FilterCapability) -> Result<(), error::ErrorCode> {
        unsafe {
            // FIXME: the underlying clone does not make a deep copy of the capability's
            //        property value, but a shallow one. For pointer values (e.g
            //        string, lists) this means that only the pointer addresses are copied, not
            //        the actual data.
            //        For now that's fine as the wrappers do not manage the life cycle of the
            //        property value. But it leak memory if it ever gets implemented.
            let mut caps_clone = caps.cap;

            let gf_err = bindings::gf_filter_push_caps(
                self.ptr,
                caps_clone.code,
                &mut caps_clone.val as *mut bindings::GF_PropertyValue,
                caps_clone.name,
                caps_clone.flags,
                caps_clone.priority,
            );

            match error::ErrorCode::from(gf_err) {
                error::ErrorCode::OK => Ok(()),
                err => Err(err),
            }
        }
    }

    pub fn get_caps(&self) -> Vec<FilterCapability> {
        unsafe {
            let mut nb_caps: u32 = 0;
            let caps_ptr = bindings::gf_filter_get_caps(self.ptr, &mut nb_caps as *mut u32);

            let mut vec = Vec::with_capacity(nb_caps as usize);

            for i in 0..nb_caps as isize {
                let c_caps = caps_ptr.offset(i);
                vec.push((*c_caps).into());
            }

            vec
        }
    }

    pub fn get_udta<T>(&self) -> Option<&mut T> {
        unsafe {
            let ptr = bindings::gf_filter_get_udta(self.ptr);

            match ptr.is_null() {
                true => None,
                false => Some(&mut (*(ptr as *mut T))),
            }
        }
    }

    pub fn new_pid(&self) -> Option<FilterPid> {
        unsafe {
            let pid_ptr = bindings::gf_filter_pid_new(self.ptr);
            FilterPid::from_ptr(pid_ptr)
        }
    }

    pub fn new_pid_raw(
        &self,
        url: Option<&str>,
        local_file: Option<&str>,
        mime_type: Option<&str>,
        fext: Option<&str>,
        probe_data: Option<&[u8]>,
        trust_mime: bool,
    ) -> Result<FilterPid, error::ErrorCode> {
        unsafe {
            let mut out_pid: *mut bindings::GF_FilterPid = std::ptr::null_mut();

            let c_trust_mime = match trust_mime {
                true => bindings::Bool_GF_TRUE,
                false => bindings::Bool_GF_FALSE,
            };

            let gf_err = bindings::gf_filter_pid_raw_new(
                self.ptr,
                url.map_or(std::ptr::null(), |it| {
                    str_util::new_unmanaged_str(it).unwrap()
                }),
                local_file.map_or(std::ptr::null(), |it| {
                    str_util::new_unmanaged_str(it).unwrap()
                }),
                mime_type.map_or(std::ptr::null(), |it| {
                    str_util::new_unmanaged_str(it).unwrap()
                }),
                fext.map_or(std::ptr::null(), |it| {
                    str_util::new_unmanaged_str(it).unwrap()
                }),
                probe_data.map_or(std::ptr::null(), |it| it.as_ptr()),
                probe_data.map_or(0, |it| it.len() as u32),
                c_trust_mime,
                &mut out_pid as *mut *mut bindings::GF_FilterPid,
            );

            match error::ErrorCode::from(gf_err) {
                error::ErrorCode::OK => match FilterPid::from_ptr(out_pid) {
                    Some(pid) => Ok(pid),
                    None => Err(error::ErrorCode::OutOfMem),
                },
                err => Err(err),
            }
        }
    }

    pub fn is_source(&self) -> bool {
        unsafe { bindings::gf_filter_is_source(self.ptr) == bindings::Bool_GF_TRUE }
    }

    pub fn is_sink(&self) -> bool {
        unsafe { bindings::gf_filter_is_sink(self.ptr) == bindings::Bool_GF_TRUE }
    }

    pub fn reconnect_outputs(&self) -> error::ErrorCode {
        unsafe {
            let gf_err = bindings::gf_filter_reconnect_output(self.ptr, std::ptr::null_mut());
            error::ErrorCode::from(gf_err)
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{bindings, BuiltInProperty, CapabilityFlags, Session};
    use crate::{ErrorCode, FilterCapability};

    #[test]
    fn test_push_one_capability() -> Result<(), ErrorCode> {
        ///////////////////////////////////////////////////////////////////////
        // Given session object and a list of filters to load
        let session = Session::new().map_or(Err(ErrorCode::OutOfMem), Ok)?;

        // and given a set of capabilities
        let input_caps = FilterCapability::new_uint(
            CapabilityFlags::Output,
            BuiltInProperty::PidStreamType,
            bindings::GF_STREAM_FILE,
        );

        ///////////////////////////////////////////////////////////////////////
        // When creating a custom filter with a given name
        let custom_filter = session.create_custom_filter("my_filter")?;

        // and pushing the caps to the filter
        custom_filter.push_caps(&input_caps)?;

        ///////////////////////////////////////////////////////////////////////
        // Then when fetching the caps from the filter
        let filter_caps = custom_filter.get_caps();

        // there should be as many as the input caps
        assert_eq!(filter_caps.len(), 1);
        assert_eq!(filter_caps[0], input_caps);

        Ok(())
    }

    #[test]
    fn test_push_one_string_capability() -> Result<(), ErrorCode> {
        ///////////////////////////////////////////////////////////////////////
        // Given session object and a list of filters to load
        let session = Session::new().map_or(Err(ErrorCode::OutOfMem), Ok)?;

        // and given a set of capabilities
        let input_caps = FilterCapability::new_string(
            CapabilityFlags::Output,
            BuiltInProperty::PidFileExt,
            "string_value.as_mut_str()",
        );

        ///////////////////////////////////////////////////////////////////////
        // When creating a custom filter with a given name
        let custom_filter = session.create_custom_filter("my_filter")?;

        // and pushing the caps to the filter
        custom_filter.push_caps(&input_caps)?;

        ////////////////////////////////////////////////////////////////////
        // Then when fetching the caps from the filter
        let filter_caps = custom_filter.get_caps();

        // there should be as many as the input caps
        assert_eq!(filter_caps.len(), 1);
        assert_eq!(filter_caps[0], input_caps);

        Ok(())
    }

    #[test]
    fn test_push_two_capabilities() -> Result<(), ErrorCode> {
        ///////////////////////////////////////////////////////////////////////
        // Given session object and a list of filters to load
        let session = Session::new().map_or(Err(ErrorCode::OutOfMem), Ok)?;

        // and given a set of capabilities
        let input_caps_1 = FilterCapability::new_uint(
            CapabilityFlags::Output,
            BuiltInProperty::PidStreamType,
            bindings::GF_STREAM_FILE,
        );

        let input_caps_2 = FilterCapability::new_uint(
            CapabilityFlags::Output,
            BuiltInProperty::PidTimescale,
            90000,
        );

        ///////////////////////////////////////////////////////////////////////
        // When creating a custom filter with a given name
        let custom_filter = session.create_custom_filter("my_filter")?;

        // and pushing the caps to the filter
        custom_filter.push_caps(&input_caps_1)?;
        custom_filter.push_caps(&input_caps_2)?;

        ///////////////////////////////////////////////////////////////////////
        // Then when fetching the caps from the filter
        let filter_caps = custom_filter.get_caps();

        // there should be as many as the input caps, and they should be equal
        assert_eq!(filter_caps.len(), 2);
        assert_eq!(filter_caps[0], input_caps_1);
        assert_eq!(filter_caps[1], input_caps_2);

        Ok(())
    }

    #[test]
    fn test_push_capabilities_from_vector() -> Result<(), ErrorCode> {
        ///////////////////////////////////////////////////////////////////////
        // Given session object and a list of filters to load
        let session = Session::new().map_or(Err(ErrorCode::OutOfMem), Ok)?;

        // and given a set of capabilities
        let input_caps = [
            FilterCapability::new_uint(
                CapabilityFlags::Output,
                BuiltInProperty::PidStreamType,
                bindings::GF_STREAM_FILE,
            ),
            FilterCapability::new_string(
                CapabilityFlags::Output,
                BuiltInProperty::PidFileExt,
                "ts|m2t|mts|dmb|trp",
            ),
            FilterCapability::new_string(
                CapabilityFlags::Output,
                BuiltInProperty::PidMime,
                "video/mpeg-2|video/mp2t|video/mpeg|audio/mp2t",
            ),
        ];

        ///////////////////////////////////////////////////////////////////////
        // When creating a custom filter with a given name
        let custom_filter = session.create_custom_filter("my_filter")?;

        // and pushing the caps to the filter
        for caps in &input_caps {
            custom_filter.push_caps(caps)?;
        }

        ///////////////////////////////////////////////////////////////////////
        // Then when fetching the caps from the filter
        let filter_caps = custom_filter.get_caps();

        // there should be as many as the input caps
        assert_eq!(filter_caps.len(), input_caps.len());

        for i in 0..filter_caps.len() {
            // and the capabilities should match.
            assert_eq!(input_caps[i], filter_caps[i]);
        }

        Ok(())
    }
}
