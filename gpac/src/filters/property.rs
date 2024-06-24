use crate::bindings;
use crate::str_util;
use std::fmt::{Debug, Formatter};

/// Creates a GF_PropertyValue with a C-string copy of the provided value.
///
/// The memory of the copied C-string is not managed by Rust. Make sure
/// that the returned value is passed to some other function that
/// takes ownership of the property value.
pub fn create_property_string(value: &str) -> bindings::GF_PropertyValue {
    let str_ptr =
        str_util::new_unmanaged_str(value).expect("Error creating string from &str reference");

    bindings::GF_PropertyValue {
        type_: bindings::GF_PropType_GF_PROP_STRING,
        value: bindings::__gf_prop_val__bindgen_ty_1 { string: str_ptr },
    }
}

pub fn create_property_bool(value: bool) -> bindings::GF_PropertyValue {
    let gf_bool = match value {
        true => bindings::Bool_GF_TRUE,
        false => bindings::Bool_GF_FALSE,
    };

    bindings::GF_PropertyValue {
        type_: bindings::GF_PropType_GF_PROP_BOOL,
        value: bindings::__gf_prop_val__bindgen_ty_1 { boolean: gf_bool },
    }
}

pub fn create_property_u32(value: u32) -> bindings::GF_PropertyValue {
    bindings::GF_PropertyValue {
        type_: bindings::GF_PropType_GF_PROP_UINT,
        value: bindings::__gf_prop_val__bindgen_ty_1 { uint: value },
    }
}

pub fn create_property_zeroed() -> bindings::GF_PropertyValue {
    bindings::GF_PropertyValue {
        type_: 0 as bindings::GF_PropType,
        value: bindings::__gf_prop_val__bindgen_ty_1 { uint: 0 },
    }
}

impl PartialEq for bindings::GF_PropertyValue {
    fn eq(&self, other: &Self) -> bool {
        let mut is_equal = self.type_ == other.type_;

        unsafe {
            is_equal = is_equal
                && match self.type_ {
                    bindings::GF_PropType_GF_PROP_UINT => self.value.uint == other.value.uint,
                    bindings::GF_PropType_GF_PROP_BOOL => self.value.boolean == other.value.boolean,
                    bindings::GF_PropType_GF_PROP_STRING => {
                        libc::strcmp(self.value.string, other.value.string) == 0
                    }
                    _ => {
                        todo!("property value not supported");
                    }
                };
        }

        is_equal
    }
}

impl Debug for bindings::GF_PropertyValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // TODO: print value according to property type.
        f.debug_struct("GF_PropertyValue")
            .field("type", &self.type_)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::{bindings, create_property_bool, create_property_string, create_property_u32};

    #[test]
    fn test_equal_u32() {
        ///////////////////////////////////////////////////////////////////////
        // Given two GF_PropertyValue instances with the same type and value
        let prop_1 = create_property_u32(0x4567);
        let prop_2 = create_property_u32(0x4567);

        ///////////////////////////////////////////////////////////////////////
        // When comparing for equality, then they should be equal
        assert_eq!(prop_1, prop_2);
    }

    #[test]
    fn test_not_equal_u32() {
        ///////////////////////////////////////////////////////////////////////
        // Given two GF_PropertyValue instances with the same type and value
        let prop_1 = create_property_u32(0x4567);
        let prop_2 = create_property_u32(0x4568);

        ///////////////////////////////////////////////////////////////////////
        // When comparing for equality, then they should not be equal
        assert_ne!(prop_1, prop_2);
    }

    #[test]
    fn test_equal_bool() {
        ///////////////////////////////////////////////////////////////////////
        // Given two GF_PropertyValue instances with the same type and value
        let prop_1 = create_property_bool(true);
        let prop_2 = create_property_bool(true);

        ///////////////////////////////////////////////////////////////////////
        // When comparing for equality, then they should be equal
        assert_eq!(prop_1, prop_2);
    }

    #[test]
    fn test_not_equal_bool() {
        ///////////////////////////////////////////////////////////////////////
        // Given two GF_PropertyValue instances with the same type and value
        let prop_1 = create_property_bool(true);
        let prop_2 = create_property_bool(false);

        ///////////////////////////////////////////////////////////////////////
        // When comparing for equality, then they should not be equal
        assert_ne!(prop_1, prop_2);
    }

    #[test]
    fn test_equal_string() {
        ///////////////////////////////////////////////////////////////////////
        // Given two GF_PropertyValue instances with the same type and value
        let mut prop_1 = create_property_string("my_string_value");
        let mut prop_2 = create_property_string("my_string_value");

        ///////////////////////////////////////////////////////////////////////
        // When comparing for equality, then they should be equal
        assert_eq!(prop_1, prop_2);

        // manually free memory
        unsafe {
            bindings::gf_props_reset_single(&mut prop_1 as *mut bindings::GF_PropertyValue);
            bindings::gf_props_reset_single(&mut prop_2 as *mut bindings::GF_PropertyValue);
        }
    }

    #[test]
    fn test_not_equal_string() {
        ///////////////////////////////////////////////////////////////////////
        // Given two GF_PropertyValue instances with the same type and value
        let mut prop_1 = create_property_string("my_string_value");
        let mut prop_2 = create_property_string("other_string_value");

        ///////////////////////////////////////////////////////////////////////
        // When comparing for equality, then they should not be equal
        assert_ne!(prop_1, prop_2);

        // manually free memory
        unsafe {
            bindings::gf_props_reset_single(&mut prop_1 as *mut bindings::GF_PropertyValue);
            bindings::gf_props_reset_single(&mut prop_2 as *mut bindings::GF_PropertyValue);
        }
    }
}
