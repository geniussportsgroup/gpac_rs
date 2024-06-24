use crate::bindings::GF_FilterCapability;
use crate::filters::property;
use crate::{bindings, BuiltInProperty};
use std::fmt::{Debug, Formatter};

///////////////////////////////////////////////////////////////////////////////
// Shortcuts for input capability flags
// As they are defined as macros in GPAC filters.h header, they are not translated
// into Rust by bindgen and have to be manually translated.
const GF_CAPS_INPUT: u32 = bindings::GF_CAPFLAG_IN_BUNDLE | bindings::GF_CAPFLAG_INPUT;
const GF_CAPS_INPUT_OPT: u32 =
    bindings::GF_CAPFLAG_IN_BUNDLE | bindings::GF_CAPFLAG_INPUT | bindings::GF_CAPFLAG_OPTIONAL;
const GF_CAPS_INPUT_STATIC: u32 =
    bindings::GF_CAPFLAG_IN_BUNDLE | bindings::GF_CAPFLAG_INPUT | bindings::GF_CAPFLAG_STATIC;
const GF_CAPS_INPUT_STATIC_OPT: u32 = bindings::GF_CAPFLAG_IN_BUNDLE
    | bindings::GF_CAPFLAG_INPUT
    | bindings::GF_CAPFLAG_STATIC
    | bindings::GF_CAPFLAG_OPTIONAL;
const GF_CAPS_INPUT_EXCLUDED: u32 =
    bindings::GF_CAPFLAG_IN_BUNDLE | bindings::GF_CAPFLAG_INPUT | bindings::GF_CAPFLAG_EXCLUDED;
const GF_CAPS_INPUT_LOADED_FILTER: u32 = bindings::GF_CAPFLAG_IN_BUNDLE
    | bindings::GF_CAPFLAG_INPUT
    | bindings::GF_CAPFLAG_LOADED_FILTER;
const GF_CAPS_OUTPUT: u32 = bindings::GF_CAPFLAG_IN_BUNDLE | bindings::GF_CAPFLAG_OUTPUT;
const GF_CAPS_OUTPUT_LOADED_FILTER: u32 = bindings::GF_CAPFLAG_IN_BUNDLE
    | bindings::GF_CAPFLAG_OUTPUT
    | bindings::GF_CAPFLAG_LOADED_FILTER;
const GF_CAPS_OUTPUT_EXCLUDED: u32 =
    bindings::GF_CAPFLAG_IN_BUNDLE | bindings::GF_CAPFLAG_OUTPUT | bindings::GF_CAPFLAG_EXCLUDED;
const GF_CAPS_OUTPUT_STATIC: u32 =
    bindings::GF_CAPFLAG_IN_BUNDLE | bindings::GF_CAPFLAG_OUTPUT | bindings::GF_CAPFLAG_STATIC;
const GF_CAPS_OUTPUT_STATIC_EXCLUDED: u32 = bindings::GF_CAPFLAG_IN_BUNDLE
    | bindings::GF_CAPFLAG_OUTPUT
    | bindings::GF_CAPFLAG_EXCLUDED
    | bindings::GF_CAPFLAG_STATIC;
const GF_CAPS_INPUT_OUTPUT: u32 =
    bindings::GF_CAPFLAG_IN_BUNDLE | bindings::GF_CAPFLAG_INPUT | bindings::GF_CAPFLAG_OUTPUT;
const GF_CAPS_INPUT_OUTPUT_OPT: u32 = bindings::GF_CAPFLAG_IN_BUNDLE
    | bindings::GF_CAPFLAG_INPUT
    | bindings::GF_CAPFLAG_OUTPUT
    | bindings::GF_CAPFLAG_OPTIONAL;
const GF_CAPS_IN_OUT_EXCLUDED: u32 = bindings::GF_CAPFLAG_IN_BUNDLE
    | bindings::GF_CAPFLAG_INPUT
    | bindings::GF_CAPFLAG_OUTPUT
    | bindings::GF_CAPFLAG_EXCLUDED;

#[repr(u32)]
pub enum CapabilityFlags {
    Input = GF_CAPS_INPUT,
    InputOpt = GF_CAPS_INPUT_OPT,
    InputStatic = GF_CAPS_INPUT_STATIC,
    InputStaticOpt = GF_CAPS_INPUT_STATIC_OPT,
    InputExcluded = GF_CAPS_INPUT_EXCLUDED,
    InputLoadedFilter = GF_CAPS_INPUT_LOADED_FILTER,
    Output = GF_CAPS_OUTPUT,
    OutputLoadedFilter = GF_CAPS_OUTPUT_LOADED_FILTER,
    OutputExcluded = GF_CAPS_OUTPUT_EXCLUDED,
    OutputStatic = GF_CAPS_OUTPUT_STATIC,
    OutputStaticExcluded = GF_CAPS_OUTPUT_STATIC_EXCLUDED,
    InputOutput = GF_CAPS_INPUT_OUTPUT,
    InputOutputOpt = GF_CAPS_INPUT_OUTPUT_OPT,
    InOutExcluded = GF_CAPS_IN_OUT_EXCLUDED,
}

impl From<CapabilityFlags> for u32 {
    fn from(val: CapabilityFlags) -> Self {
        val as u32
    }
}

pub struct FilterCapability {
    pub(crate) cap: bindings::GF_FilterCapability,
}

impl FilterCapability {
    pub fn new_uint(flags: CapabilityFlags, property: BuiltInProperty, value: u32) -> Self {
        FilterCapability {
            cap: bindings::GF_FilterCapability {
                code: property.into(),
                flags: flags.into(),
                name: std::ptr::null(),
                priority: 0,
                val: property::create_property_u32(value),
            },
        }
    }

    pub fn new_bool(flags: CapabilityFlags, property: BuiltInProperty, value: bool) -> Self {
        FilterCapability {
            cap: bindings::GF_FilterCapability {
                code: property.into(),
                flags: flags.into(),
                name: std::ptr::null(),
                priority: 0,
                val: property::create_property_bool(value),
            },
        }
    }

    pub fn new_string(
        flags: CapabilityFlags,
        property: BuiltInProperty,
        value: &'static str,
    ) -> Self {
        FilterCapability {
            cap: bindings::GF_FilterCapability {
                code: property.into(),
                flags: flags.into(),
                name: std::ptr::null(),
                priority: 0,
                val: property::create_property_string(value),
            },
        }
    }

    pub fn new_zeroed() -> Self {
        Self {
            cap: bindings::GF_FilterCapability {
                code: 0x00,
                flags: 0x00,
                name: std::ptr::null(),
                priority: 0,
                val: property::create_property_zeroed(),
            },
        }
    }
}

impl From<FilterCapability> for bindings::GF_FilterCapability {
    fn from(val: FilterCapability) -> Self {
        val.cap
    }
}

impl From<GF_FilterCapability> for FilterCapability {
    fn from(value: GF_FilterCapability) -> Self {
        Self { cap: value }
    }
}

impl PartialEq for FilterCapability {
    fn eq(&self, other: &Self) -> bool {
        self.cap.code == other.cap.code
            && self.cap.flags == other.cap.flags
            && self.cap.priority == other.cap.priority
            && self.cap.name == other.cap.name
            && self.cap.val.eq(&other.cap.val)
    }
}

impl Debug for FilterCapability {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilterCapability").finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::{bindings, BuiltInProperty, CapabilityFlags, FilterCapability};

    #[test]
    fn test_create_capability() {
        ///////////////////////////////////////////////////////////////////////
        // Given a scope
        {
            ///////////////////////////////////////////////////////////////////
            // When creating a FilterCapability
            let caps = FilterCapability::new_uint(
                CapabilityFlags::Output,
                BuiltInProperty::PidStreamType,
                bindings::GF_STREAM_FILE,
            );

            assert_eq!(caps.cap.flags, CapabilityFlags::Output.into());
            assert_eq!(caps.cap.code, BuiltInProperty::PidStreamType.into());
            assert_eq!(caps.cap.val.type_, bindings::GF_PropType_GF_PROP_UINT);
            unsafe {
                assert_eq!(caps.cap.val.value.uint, bindings::GF_STREAM_FILE);
            }
        }

        ///////////////////////////////////////////////////////////////////////
        // Then the FilterCapability should be freed without any panic
    }

    #[test]
    fn test_create_string_capability() {
        ///////////////////////////////////////////////////////////////////////
        // Given a scope
        {
            ///////////////////////////////////////////////////////////////////
            // When creating a FilterCapability
            let caps = FilterCapability::new_string(
                CapabilityFlags::Output,
                BuiltInProperty::PidStreamType,
                "my_string_value",
            );

            assert_eq!(caps.cap.flags, CapabilityFlags::Output.into());
            assert_eq!(caps.cap.code, BuiltInProperty::PidStreamType.into());
            assert_eq!(caps.cap.val.type_, bindings::GF_PropType_GF_PROP_STRING);
            // unsafe {
            //     assert_eq!(caps.cap.val.value.string, bindings::GF_STREAM_FILE);
            // }
        }

        ///////////////////////////////////////////////////////////////////////
        // Then the FilterCapability should be freed without any panic
    }

    #[test]
    fn test_create_capabilities_vector() {
        ///////////////////////////////////////////////////////////////////////
        // Given a scope
        {
            ///////////////////////////////////////////////////////////////////
            // When creating a vector of FilterCapabilities
            let caps = [
                FilterCapability::new_uint(
                    CapabilityFlags::Output,
                    BuiltInProperty::PidStreamType,
                    bindings::GF_STREAM_FILE,
                ),
                // NOTE: enabling these two capabilities makes the filter to no longer appear as a source
                FilterCapability::new_string(
                    CapabilityFlags::Output,
                    BuiltInProperty::PidFileExt,
                    "ts|m2t|mts|dmb|trp", // taken from M2TS_FILE_EXTS at mux_ts.c
                ),
                FilterCapability::new_string(
                    CapabilityFlags::Output,
                    BuiltInProperty::PidMime,
                    "video/mpeg-2|video/mp2t|video/mpeg|audio/mp2t", // taken from M2TS_MIMES at mux_ts.c
                ),
            ];

            assert_eq!(caps.len(), 3);
        }

        ///////////////////////////////////////////////////////////////////////
        // Then the vector should be freed without any panic
    }
}
