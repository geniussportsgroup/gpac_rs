use crate::bindings;
use std::fmt::{Display, Formatter};

// only needed for test
#[cfg(test)]
use strum_macros::EnumIter;

const ENUM_TO_STRING_ERROR_MSG: &str = "ERROR transforming from GF ERROR to string";

#[repr(i32)]
#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(test, derive(EnumIter))] // only needed for tests
pub enum ErrorCode {
    ScriptInfo = bindings::GF_Err_GF_SCRIPT_INFO,
    PendingPacket = bindings::GF_Err_GF_PENDING_PACKET,
    EOS = bindings::GF_Err_GF_EOS,
    OK = bindings::GF_Err_GF_OK,
    BadParam = bindings::GF_Err_GF_BAD_PARAM,
    OutOfMem = bindings::GF_Err_GF_OUT_OF_MEM,
    IoErr = bindings::GF_Err_GF_IO_ERR,
    NotSupported = bindings::GF_Err_GF_NOT_SUPPORTED,
    CorruptedData = bindings::GF_Err_GF_CORRUPTED_DATA,
    SgUnknownNode = bindings::GF_Err_GF_SG_UNKNOWN_NODE,
    SgInvalidProto = bindings::GF_Err_GF_SG_INVALID_PROTO,
    ScriptError = bindings::GF_Err_GF_SCRIPT_ERROR,
    BufferTooSmall = bindings::GF_Err_GF_BUFFER_TOO_SMALL,
    NonCompliantBitstream = bindings::GF_Err_GF_NON_COMPLIANT_BITSTREAM,
    FilterNotFound = bindings::GF_Err_GF_FILTER_NOT_FOUND,
    UrlError = bindings::GF_Err_GF_URL_ERROR,
    ServiceError = bindings::GF_Err_GF_SERVICE_ERROR,
    RemoteServiceError = bindings::GF_Err_GF_REMOTE_SERVICE_ERROR,
    StreamNotFound = bindings::GF_Err_GF_STREAM_NOT_FOUND,
    UrlRemoved = bindings::GF_Err_GF_URL_REMOVED,
    IsomInvalidFile = bindings::GF_Err_GF_ISOM_INVALID_FILE,
    IsomIncompleteFile = bindings::GF_Err_GF_ISOM_INCOMPLETE_FILE,
    IsomInvalidMedia = bindings::GF_Err_GF_ISOM_INVALID_MEDIA,
    IsomInvalidMode = bindings::GF_Err_GF_ISOM_INVALID_MODE,
    IsomUnknownDataRef = bindings::GF_Err_GF_ISOM_UNKNOWN_DATA_REF,
    OdfInvalidDescriptor = bindings::GF_Err_GF_ODF_INVALID_DESCRIPTOR,
    OdfForbiddenDescriptor = bindings::GF_Err_GF_ODF_FORBIDDEN_DESCRIPTOR,
    OdfInvalidCommand = bindings::GF_Err_GF_ODF_INVALID_COMMAND,
    BifsUnknownVersion = bindings::GF_Err_GF_BIFS_UNKNOWN_VERSION,
    IpAddressNotFound = bindings::GF_Err_GF_IP_ADDRESS_NOT_FOUND,
    IpConnectionFailure = bindings::GF_Err_GF_IP_CONNECTION_FAILURE,
    IpNetworkFailure = bindings::GF_Err_GF_IP_NETWORK_FAILURE,
    IpConnectionClosed = bindings::GF_Err_GF_IP_CONNECTION_CLOSED,
    IpNetworkEmpty = bindings::GF_Err_GF_IP_NETWORK_EMPTY,
    IpUdpTimeout = bindings::GF_Err_GF_IP_UDP_TIMEOUT,
    AuthenticationFailure = bindings::GF_Err_GF_AUTHENTICATION_FAILURE,
    NotReady = bindings::GF_Err_GF_NOT_READY,
    InvalidConfiguration = bindings::GF_Err_GF_INVALID_CONFIGURATION,
    NotFound = bindings::GF_Err_GF_NOT_FOUND,
    ProfileNotSupported = bindings::GF_Err_GF_PROFILE_NOT_SUPPORTED,
    RequiresNewInstance = bindings::GF_Err_GF_REQUIRES_NEW_INSTANCE,
    FilterNotSupported = bindings::GF_Err_GF_FILTER_NOT_SUPPORTED,
    RustEnumConversionError = -1000,
    RustSyncError = -1001,
}

impl From<i32> for ErrorCode {
    fn from(value: i32) -> Self {
        match value {
            bindings::GF_Err_GF_SCRIPT_INFO => ErrorCode::ScriptInfo,
            bindings::GF_Err_GF_PENDING_PACKET => ErrorCode::PendingPacket,
            bindings::GF_Err_GF_EOS => ErrorCode::EOS,
            bindings::GF_Err_GF_OK => ErrorCode::OK,
            bindings::GF_Err_GF_BAD_PARAM => ErrorCode::BadParam,
            bindings::GF_Err_GF_OUT_OF_MEM => ErrorCode::OutOfMem,
            bindings::GF_Err_GF_IO_ERR => ErrorCode::IoErr,
            bindings::GF_Err_GF_NOT_SUPPORTED => ErrorCode::NotSupported,
            bindings::GF_Err_GF_CORRUPTED_DATA => ErrorCode::CorruptedData,
            bindings::GF_Err_GF_SG_UNKNOWN_NODE => ErrorCode::SgUnknownNode,
            bindings::GF_Err_GF_SG_INVALID_PROTO => ErrorCode::SgInvalidProto,
            bindings::GF_Err_GF_SCRIPT_ERROR => ErrorCode::ScriptError,
            bindings::GF_Err_GF_BUFFER_TOO_SMALL => ErrorCode::BufferTooSmall,
            bindings::GF_Err_GF_NON_COMPLIANT_BITSTREAM => ErrorCode::NonCompliantBitstream,
            bindings::GF_Err_GF_FILTER_NOT_FOUND => ErrorCode::FilterNotFound,
            bindings::GF_Err_GF_URL_ERROR => ErrorCode::UrlError,
            bindings::GF_Err_GF_SERVICE_ERROR => ErrorCode::ServiceError,
            bindings::GF_Err_GF_REMOTE_SERVICE_ERROR => ErrorCode::RemoteServiceError,
            bindings::GF_Err_GF_STREAM_NOT_FOUND => ErrorCode::StreamNotFound,
            bindings::GF_Err_GF_URL_REMOVED => ErrorCode::UrlRemoved,
            bindings::GF_Err_GF_ISOM_INVALID_FILE => ErrorCode::IsomInvalidFile,
            bindings::GF_Err_GF_ISOM_INCOMPLETE_FILE => ErrorCode::IsomIncompleteFile,
            bindings::GF_Err_GF_ISOM_INVALID_MEDIA => ErrorCode::IsomInvalidMedia,
            bindings::GF_Err_GF_ISOM_INVALID_MODE => ErrorCode::IsomInvalidMode,
            bindings::GF_Err_GF_ISOM_UNKNOWN_DATA_REF => ErrorCode::IsomUnknownDataRef,
            bindings::GF_Err_GF_ODF_INVALID_DESCRIPTOR => ErrorCode::OdfInvalidDescriptor,
            bindings::GF_Err_GF_ODF_FORBIDDEN_DESCRIPTOR => ErrorCode::OdfForbiddenDescriptor,
            bindings::GF_Err_GF_ODF_INVALID_COMMAND => ErrorCode::OdfInvalidCommand,
            bindings::GF_Err_GF_BIFS_UNKNOWN_VERSION => ErrorCode::BifsUnknownVersion,
            bindings::GF_Err_GF_IP_ADDRESS_NOT_FOUND => ErrorCode::IpAddressNotFound,
            bindings::GF_Err_GF_IP_CONNECTION_FAILURE => ErrorCode::IpConnectionFailure,
            bindings::GF_Err_GF_IP_NETWORK_FAILURE => ErrorCode::IpNetworkFailure,
            bindings::GF_Err_GF_IP_CONNECTION_CLOSED => ErrorCode::IpConnectionClosed,
            bindings::GF_Err_GF_IP_NETWORK_EMPTY => ErrorCode::IpNetworkEmpty,
            bindings::GF_Err_GF_IP_UDP_TIMEOUT => ErrorCode::IpUdpTimeout,
            bindings::GF_Err_GF_AUTHENTICATION_FAILURE => ErrorCode::AuthenticationFailure,
            bindings::GF_Err_GF_NOT_READY => ErrorCode::NotReady,
            bindings::GF_Err_GF_INVALID_CONFIGURATION => ErrorCode::InvalidConfiguration,
            bindings::GF_Err_GF_NOT_FOUND => ErrorCode::NotFound,
            bindings::GF_Err_GF_PROFILE_NOT_SUPPORTED => ErrorCode::ProfileNotSupported,
            bindings::GF_Err_GF_REQUIRES_NEW_INSTANCE => ErrorCode::RequiresNewInstance,
            bindings::GF_Err_GF_FILTER_NOT_SUPPORTED => ErrorCode::FilterNotSupported,
            _ => ErrorCode::RustEnumConversionError,
        }
    }
}

impl From<ErrorCode> for i32 {
    fn from(val: ErrorCode) -> Self {
        val as i32
    }
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let gf_err: bindings::GF_Err = *self as bindings::GF_Err;
        write!(f, "{}", gf_err_to_string(gf_err))
    }
}

fn gf_err_to_string(gf_err: bindings::GF_Err) -> String {
    unsafe {
        let c_str = bindings::gf_error_to_string(gf_err);
        let rusty_str = std::ffi::CStr::from_ptr(c_str);
        return rusty_str
            .to_str()
            .unwrap_or(ENUM_TO_STRING_ERROR_MSG)
            .to_string();
    }
}

#[cfg(test)]
mod tests {
    use crate::bindings;
    use crate::filters::error;
    use crate::filters::error::{gf_err_to_string, ErrorCode, ENUM_TO_STRING_ERROR_MSG};
    use strum::IntoEnumIterator;

    // Boundaries of the open interval for the error values.
    // The last valid values are:
    // - MIN_ERROR_VALUE + 1
    // - MAX_ERROR_VALUE -1
    const MIN_ERROR_VALUE: i32 = -58i32;
    const MAX_ERROR_VALUE: i32 = 4i32;

    // Actual numeric values of the available error codes.
    // NOTE: They are not a sequence of numbers in the
    //       interval (MIN_ERROR_VALUE, MAX_ERROR_VALUE).
    const VALID_ERROR_CODES: [bindings::GF_Err; 42] = [
        bindings::GF_Err_GF_SCRIPT_INFO,
        bindings::GF_Err_GF_PENDING_PACKET,
        bindings::GF_Err_GF_EOS,
        bindings::GF_Err_GF_OK,
        bindings::GF_Err_GF_BAD_PARAM,
        bindings::GF_Err_GF_OUT_OF_MEM,
        bindings::GF_Err_GF_IO_ERR,
        bindings::GF_Err_GF_NOT_SUPPORTED,
        bindings::GF_Err_GF_CORRUPTED_DATA,
        bindings::GF_Err_GF_SG_UNKNOWN_NODE,
        bindings::GF_Err_GF_SG_INVALID_PROTO,
        bindings::GF_Err_GF_SCRIPT_ERROR,
        bindings::GF_Err_GF_BUFFER_TOO_SMALL,
        bindings::GF_Err_GF_NON_COMPLIANT_BITSTREAM,
        bindings::GF_Err_GF_FILTER_NOT_FOUND,
        bindings::GF_Err_GF_URL_ERROR,
        bindings::GF_Err_GF_SERVICE_ERROR,
        bindings::GF_Err_GF_REMOTE_SERVICE_ERROR,
        bindings::GF_Err_GF_STREAM_NOT_FOUND,
        bindings::GF_Err_GF_URL_REMOVED,
        bindings::GF_Err_GF_ISOM_INVALID_FILE,
        bindings::GF_Err_GF_ISOM_INCOMPLETE_FILE,
        bindings::GF_Err_GF_ISOM_INVALID_MEDIA,
        bindings::GF_Err_GF_ISOM_INVALID_MODE,
        bindings::GF_Err_GF_ISOM_UNKNOWN_DATA_REF,
        bindings::GF_Err_GF_ODF_INVALID_DESCRIPTOR,
        bindings::GF_Err_GF_ODF_FORBIDDEN_DESCRIPTOR,
        bindings::GF_Err_GF_ODF_INVALID_COMMAND,
        bindings::GF_Err_GF_BIFS_UNKNOWN_VERSION,
        bindings::GF_Err_GF_IP_ADDRESS_NOT_FOUND,
        bindings::GF_Err_GF_IP_CONNECTION_FAILURE,
        bindings::GF_Err_GF_IP_NETWORK_FAILURE,
        bindings::GF_Err_GF_IP_CONNECTION_CLOSED,
        bindings::GF_Err_GF_IP_NETWORK_EMPTY,
        bindings::GF_Err_GF_IP_UDP_TIMEOUT,
        bindings::GF_Err_GF_AUTHENTICATION_FAILURE,
        bindings::GF_Err_GF_NOT_READY,
        bindings::GF_Err_GF_INVALID_CONFIGURATION,
        bindings::GF_Err_GF_NOT_FOUND,
        bindings::GF_Err_GF_PROFILE_NOT_SUPPORTED,
        bindings::GF_Err_GF_REQUIRES_NEW_INSTANCE,
        bindings::GF_Err_GF_FILTER_NOT_SUPPORTED,
    ];

    /// This test is useful to validate that the wrappers cover all the numeric values
    /// of the GF_Err type. Currently, the lower and upper bound are the open interval
    /// (-58, 4).
    ///
    /// In case new error values are added, they need to manually be added to the
    /// ErrorCode enum above, and the boundaries of this test changed.
    #[test]
    fn test_should_return_error_on_boundaries() {
        ///////////////////////////////////////////////////////////////////////
        // Given the boundaries of GF_Err
        let gf_err_arr: [bindings::GF_Err; 2] = [MAX_ERROR_VALUE, MIN_ERROR_VALUE];
        let expected_error_messages = ["Unknown Error (4)", "Unknown Error (-58)"];

        for i in 0..gf_err_arr.len() {
            let gf_err = gf_err_arr[i];
            let expected_message = expected_error_messages[i];

            ///////////////////////////////////////////////////////////////////
            // when converting the error value to string
            let str_value = gf_err_to_string(gf_err);

            ///////////////////////////////////////////////////////////////////
            // then the value should be equal to the error message
            assert_eq!(str_value.as_str(), expected_message);
        }
    }

    #[test]
    fn test_should_convert_to_string() {
        ///////////////////////////////////////////////////////////////////////
        // Given every possible error code
        for error_code in ErrorCode::iter() {
            ///////////////////////////////////////////////////////////////////
            // When converting the enum value to string
            let str_value = error_code.to_string();

            ///////////////////////////////////////////////////////////////////
            // Then the result should not be an error message.
            assert_ne!(str_value.as_str(), ENUM_TO_STRING_ERROR_MSG);

            // And the result should have length greater than zero
            assert!(!str_value.is_empty());
        }
    }

    #[test]
    fn test_should_convert_from_i32_in_bounds() {
        ///////////////////////////////////////////////////////////////////////
        // Given all the numeric values in the valid range of errors
        for i in VALID_ERROR_CODES {
            ///////////////////////////////////////////////////////////////////
            // when trying to convert to the ErrorCode enum
            let error_code_result = error::ErrorCode::try_from(i);

            ///////////////////////////////////////////////////////////////////
            // Then the result should be ok
            assert!(error_code_result.is_ok())
        }
    }

    #[test]
    fn test_should_not_fail_converting_i32_out_of_bounds() {
        ///////////////////////////////////////////////////////////////////////
        // Given the boundaries of GF_Err
        let gf_err_arr: [i32; 2] = [MAX_ERROR_VALUE, MIN_ERROR_VALUE];

        for gf_err in &gf_err_arr {
            ///////////////////////////////////////////////////////////////////
            // when converting the error value to enumeration
            let error_code_result = error::ErrorCode::try_from(*gf_err);

            ///////////////////////////////////////////////////////////////////
            // then the result should be OK and the enum value should be RustEnumConversionError
            assert!(
                error_code_result.is_ok_and(|err| err == error::ErrorCode::RustEnumConversionError)
            );
        }
    }
}
