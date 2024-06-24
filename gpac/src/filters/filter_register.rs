use crate::bindings;
use std::fmt;
use std::fmt::Formatter;
use std::str::Utf8Error;

#[derive(Clone, Copy)]
pub struct FilterRegister {
    pub(crate) binding: bindings::GF_FilterRegister,
}

impl FilterRegister {
    /// Create a new FilterRegister from a pointer to the raw bindings object
    ///
    /// This function is accessible only from within the crate, as the internal
    /// implementation of Session::get_filter_register uses pointers to the raw
    /// GF_FilterRegister object.
    ///
    /// For users of the library, use
    pub(crate) fn from_ptr(ptr: *const bindings::GF_FilterRegister) -> Option<Self> {
        unsafe {
            match ptr.is_null() {
                true => None,
                false => Some(FilterRegister { binding: *ptr }),
            }
        }
    }

    pub fn from_raw_binding(binding: bindings::GF_FilterRegister) -> Option<Self> {
        let ptr = &binding as *const bindings::GF_FilterRegister;
        Self::from_ptr(ptr)
    }

    pub fn name(&self) -> Result<&str, Utf8Error> {
        unsafe { std::ffi::CStr::from_ptr(self.binding.name).to_str() }
    }
}

impl std::fmt::Debug for FilterRegister {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FilterRegister")
            .field("name", &self.name().unwrap_or("UTF-8 ERROR"))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::{ErrorCode, Session};

    #[test]
    fn test_filter_register_common_properties() -> Result<(), ErrorCode> {
        ///////////////////////////////////////////////////////////////////////
        // Given session object and the available filter count
        let session = Session::new()?;

        ///////////////////////////////////////////////////////////////////////
        // When obtaining the filter register for all available filters
        let filter_register_count = session.get_filter_register_count()?;
        for i in 0..filter_register_count {
            ///////////////////////////////////////////////////////////////////
            // Then the result should be Some
            let filter_register = session.get_filter_register(i)?;

            // and the filter should have a name
            let name_result = filter_register.name();
            assert!(name_result.is_ok_and(|name| !name.is_empty()));
        }

        Ok(())
    }
}
