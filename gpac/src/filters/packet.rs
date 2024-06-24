use crate::filters::error;
use crate::{bindings, FilterPid};

pub struct Packet {
    pub(crate) ptr: *mut bindings::GF_FilterPacket,
}

impl Packet {
    pub fn from_ptr(ptr: *mut bindings::GF_FilterPacket) -> Option<Self> {
        match ptr.is_null() {
            true => None,
            false => Some(Packet { ptr }),
        }
    }

    pub fn new_clone(&self, pid: &FilterPid) -> Option<Self> {
        unsafe {
            let out_data: *mut u8 = std::ptr::null_mut();
            let packet_ptr =
                bindings::gf_filter_pck_new_clone(pid.ptr, self.ptr, out_data as *mut *mut u8);

            Packet::from_ptr(packet_ptr)
        }
    }

    pub fn send(&self) -> error::ErrorCode {
        unsafe {
            let gf_err = bindings::gf_filter_pck_send(self.ptr);
            error::ErrorCode::from(gf_err)
        }
    }

    pub fn get_dts(&self) -> u64 {
        unsafe { bindings::gf_filter_pck_get_dts(self.ptr) }
    }
}
