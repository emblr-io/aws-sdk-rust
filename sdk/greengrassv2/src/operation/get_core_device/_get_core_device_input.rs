// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetCoreDeviceInput {
    /// <p>The name of the core device. This is also the name of the IoT thing.</p>
    pub core_device_thing_name: ::std::option::Option<::std::string::String>,
}
impl GetCoreDeviceInput {
    /// <p>The name of the core device. This is also the name of the IoT thing.</p>
    pub fn core_device_thing_name(&self) -> ::std::option::Option<&str> {
        self.core_device_thing_name.as_deref()
    }
}
impl GetCoreDeviceInput {
    /// Creates a new builder-style object to manufacture [`GetCoreDeviceInput`](crate::operation::get_core_device::GetCoreDeviceInput).
    pub fn builder() -> crate::operation::get_core_device::builders::GetCoreDeviceInputBuilder {
        crate::operation::get_core_device::builders::GetCoreDeviceInputBuilder::default()
    }
}

/// A builder for [`GetCoreDeviceInput`](crate::operation::get_core_device::GetCoreDeviceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetCoreDeviceInputBuilder {
    pub(crate) core_device_thing_name: ::std::option::Option<::std::string::String>,
}
impl GetCoreDeviceInputBuilder {
    /// <p>The name of the core device. This is also the name of the IoT thing.</p>
    /// This field is required.
    pub fn core_device_thing_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.core_device_thing_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the core device. This is also the name of the IoT thing.</p>
    pub fn set_core_device_thing_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.core_device_thing_name = input;
        self
    }
    /// <p>The name of the core device. This is also the name of the IoT thing.</p>
    pub fn get_core_device_thing_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.core_device_thing_name
    }
    /// Consumes the builder and constructs a [`GetCoreDeviceInput`](crate::operation::get_core_device::GetCoreDeviceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_core_device::GetCoreDeviceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_core_device::GetCoreDeviceInput {
            core_device_thing_name: self.core_device_thing_name,
        })
    }
}
