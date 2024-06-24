use crate::filters::{builtin_properties, error, property};
use crate::{bindings, Packet};
use std::str::Utf8Error;

#[derive(Eq, PartialEq)]
pub struct FilterPid {
    pub(crate) ptr: *mut bindings::GF_FilterPid,
}

///////////////////////////////////////////////////////////////////////////////
// Trait implementations

unsafe impl Send for FilterPid {}
unsafe impl Sync for FilterPid {}

///////////////////////////////////////////////////////////////////////////////
impl FilterPid {
    pub fn from_ptr(ptr: *mut bindings::GF_FilterPid) -> Option<Self> {
        match ptr.is_null() {
            true => None,
            false => Some(FilterPid { ptr }),
        }
    }

    pub fn name(&self) -> Result<&str, Utf8Error> {
        unsafe { std::ffi::CStr::from_ptr(bindings::gf_filter_pid_get_name(self.ptr)).to_str() }
    }

    pub fn copy_properties(&self, to: &mut Self) -> Result<(), error::ErrorCode> {
        unsafe {
            let gf_err = bindings::gf_filter_pid_copy_properties(to.ptr, self.ptr);
            match error::ErrorCode::from(gf_err) {
                error::ErrorCode::OK => Ok(()),
                err => Err(err),
            }
        }
    }

    pub fn get_packet(&self) -> Option<Packet> {
        unsafe {
            let packet_ptr = bindings::gf_filter_pid_get_packet(self.ptr);
            Packet::from_ptr(packet_ptr)
        }
    }

    pub fn drop_packet(&self) {
        unsafe {
            bindings::gf_filter_pid_drop_packet(self.ptr);
        }
    }

    pub fn eos_received(&self) -> bool {
        unsafe { bindings::gf_filter_pid_eos_received(self.ptr) == bindings::Bool_GF_TRUE }
    }

    pub fn set_eos(&self) {
        unsafe {
            bindings::gf_filter_pid_set_eos(self.ptr);
        }
    }

    pub fn set_name(&self, name: &str) -> Result<(), std::ffi::NulError> {
        unsafe {
            let c_name = std::ffi::CString::new(name)?;
            // internally, this method performs a strdup on c_name. No need to give up ownership.
            bindings::gf_filter_pid_set_name(self.ptr, c_name.as_ptr());
        }

        Ok(())
    }

    pub fn set_property_string(&self, code: builtin_properties::BuiltInProperty, value: &str) {
        unsafe {
            // NOTE: the implementation of gf_filter_pid_set_property makes a copy of the
            //       property value, so it's safe to pass the pointer and prop_value being
            //       dropped after the call of this function.
            //       See gf_props_assign_value in filter_props.c
            let prop_value = property::create_property_string(value);
            bindings::gf_filter_pid_set_property(
                self.ptr,
                code.into(),
                &prop_value as *const bindings::GF_PropertyValue,
            );
        }
    }
    pub fn set_property_u32(&self, code: builtin_properties::BuiltInProperty, value: u32) {
        unsafe {
            // NOTE: the implementation of gf_filter_pid_set_property makes a copy of the
            //       property value, so it's safe to pass the pointer and prop_value being
            //       dropped after the call of this function.
            //       See gf_props_assign_value in filter_props.c
            let prop_value = property::create_property_u32(value);
            bindings::gf_filter_pid_set_property(
                self.ptr,
                code.into(),
                &prop_value as *const bindings::GF_PropertyValue,
            );
        }
    }

    pub fn set_property_bool(&self, code: builtin_properties::BuiltInProperty, value: bool) {
        unsafe {
            // NOTE: the implementation of gf_filter_pid_set_property makes a copy of the
            //       property value, so it's safe to pass the pointer and prop_value being
            //       dropped after the call of this function.
            //       See gf_props_assign_value in filter_props.c
            let prop_value = property::create_property_bool(value);
            bindings::gf_filter_pid_set_property(
                self.ptr,
                code.into(),
                &prop_value as *const bindings::GF_PropertyValue,
            );
        }
    }

    pub fn set_property_null(&self, code: builtin_properties::BuiltInProperty) {
        unsafe {
            bindings::gf_filter_pid_set_property(self.ptr, code.into(), std::ptr::null());
        }
    }

    pub fn new_packet(&self, data_size: u32) -> Option<Packet> {
        unsafe {
            let mut data_ptr: *mut u8 = std::ptr::null_mut();
            let pck_ptr = bindings::gf_filter_pck_new_alloc(
                self.ptr,
                data_size,
                &mut data_ptr as *mut *mut u8,
            );

            // I ignore the returned data_ptr from gf_filter_pck_new_alloc. Users of this returned
            // packet should access the underlying data using the safe Packet API.
            Packet::from_ptr(pck_ptr)
        }
    }

    pub fn new_packet_from_data(&self, data: &[u8]) -> Option<Packet> {
        unsafe {
            let data_size = data.len() as u32;

            let mut data_ptr: *mut u8 = std::ptr::null_mut();
            let pck_ptr = bindings::gf_filter_pck_new_alloc(
                self.ptr,
                data_size,
                &mut data_ptr as *mut *mut u8,
            );

            match data_ptr.is_null() {
                true => None,
                false => {
                    std::ptr::copy_nonoverlapping(data.as_ptr(), data_ptr, data_size as usize);
                    Packet::from_ptr(pck_ptr)
                }
            }
        }
    }
}
