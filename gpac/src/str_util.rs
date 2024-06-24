use std::ffi::NulError;

pub fn new_unmanaged_str(value: &str) -> Result<*mut std::os::raw::c_char, NulError> {
    unsafe {
        let c_string = std::ffi::CString::new(value)?;

        let c_buffer = c_string.as_bytes_with_nul();
        let ptr = libc::malloc(c_buffer.len());
        std::ptr::copy_nonoverlapping(c_buffer.as_ptr(), ptr as *mut u8, c_buffer.len());

        Ok(ptr as *mut std::os::raw::c_char)
    }
}

#[cfg(test)]
mod tests {
    use crate::str_util::new_unmanaged_str;

    #[test]
    fn test_create_unmanaged_str() {
        ///////////////////////////////////////////////////////////////////////
        // Given a string
        let string_value = "my_string";

        ///////////////////////////////////////////////////////////////////////
        // When creating an unmanaged C string
        let c_string_result = new_unmanaged_str(string_value);

        ///////////////////////////////////////////////////////////////////////
        // Then the result should be OK
        assert!(c_string_result.is_ok());

        unsafe {
            // and the C string should contain the same byte values
            // up to the Rust string length
            let c_string = c_string_result.unwrap();
            assert_eq!(
                libc::memcmp(
                    c_string as *const libc::c_void,
                    string_value.as_ptr() as *const libc::c_void,
                    string_value.len()
                ),
                0
            );

            // manual memory free
            libc::free(c_string as *mut libc::c_void);
        }
    }
}
