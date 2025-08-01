// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Placeholder documentation for StartInputDeviceRequest
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartInputDeviceInput {
    /// The unique ID of the input device to start. For example, hd-123456789abcdef.
    pub input_device_id: ::std::option::Option<::std::string::String>,
}
impl StartInputDeviceInput {
    /// The unique ID of the input device to start. For example, hd-123456789abcdef.
    pub fn input_device_id(&self) -> ::std::option::Option<&str> {
        self.input_device_id.as_deref()
    }
}
impl StartInputDeviceInput {
    /// Creates a new builder-style object to manufacture [`StartInputDeviceInput`](crate::operation::start_input_device::StartInputDeviceInput).
    pub fn builder() -> crate::operation::start_input_device::builders::StartInputDeviceInputBuilder {
        crate::operation::start_input_device::builders::StartInputDeviceInputBuilder::default()
    }
}

/// A builder for [`StartInputDeviceInput`](crate::operation::start_input_device::StartInputDeviceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartInputDeviceInputBuilder {
    pub(crate) input_device_id: ::std::option::Option<::std::string::String>,
}
impl StartInputDeviceInputBuilder {
    /// The unique ID of the input device to start. For example, hd-123456789abcdef.
    /// This field is required.
    pub fn input_device_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.input_device_id = ::std::option::Option::Some(input.into());
        self
    }
    /// The unique ID of the input device to start. For example, hd-123456789abcdef.
    pub fn set_input_device_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.input_device_id = input;
        self
    }
    /// The unique ID of the input device to start. For example, hd-123456789abcdef.
    pub fn get_input_device_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.input_device_id
    }
    /// Consumes the builder and constructs a [`StartInputDeviceInput`](crate::operation::start_input_device::StartInputDeviceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::start_input_device::StartInputDeviceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::start_input_device::StartInputDeviceInput {
            input_device_id: self.input_device_id,
        })
    }
}
