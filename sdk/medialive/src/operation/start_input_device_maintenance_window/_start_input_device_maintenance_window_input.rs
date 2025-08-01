// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Placeholder documentation for StartInputDeviceMaintenanceWindowRequest
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartInputDeviceMaintenanceWindowInput {
    /// The unique ID of the input device to start a maintenance window for. For example, hd-123456789abcdef.
    pub input_device_id: ::std::option::Option<::std::string::String>,
}
impl StartInputDeviceMaintenanceWindowInput {
    /// The unique ID of the input device to start a maintenance window for. For example, hd-123456789abcdef.
    pub fn input_device_id(&self) -> ::std::option::Option<&str> {
        self.input_device_id.as_deref()
    }
}
impl StartInputDeviceMaintenanceWindowInput {
    /// Creates a new builder-style object to manufacture [`StartInputDeviceMaintenanceWindowInput`](crate::operation::start_input_device_maintenance_window::StartInputDeviceMaintenanceWindowInput).
    pub fn builder() -> crate::operation::start_input_device_maintenance_window::builders::StartInputDeviceMaintenanceWindowInputBuilder {
        crate::operation::start_input_device_maintenance_window::builders::StartInputDeviceMaintenanceWindowInputBuilder::default()
    }
}

/// A builder for [`StartInputDeviceMaintenanceWindowInput`](crate::operation::start_input_device_maintenance_window::StartInputDeviceMaintenanceWindowInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartInputDeviceMaintenanceWindowInputBuilder {
    pub(crate) input_device_id: ::std::option::Option<::std::string::String>,
}
impl StartInputDeviceMaintenanceWindowInputBuilder {
    /// The unique ID of the input device to start a maintenance window for. For example, hd-123456789abcdef.
    /// This field is required.
    pub fn input_device_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.input_device_id = ::std::option::Option::Some(input.into());
        self
    }
    /// The unique ID of the input device to start a maintenance window for. For example, hd-123456789abcdef.
    pub fn set_input_device_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.input_device_id = input;
        self
    }
    /// The unique ID of the input device to start a maintenance window for. For example, hd-123456789abcdef.
    pub fn get_input_device_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.input_device_id
    }
    /// Consumes the builder and constructs a [`StartInputDeviceMaintenanceWindowInput`](crate::operation::start_input_device_maintenance_window::StartInputDeviceMaintenanceWindowInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::start_input_device_maintenance_window::StartInputDeviceMaintenanceWindowInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::start_input_device_maintenance_window::StartInputDeviceMaintenanceWindowInput {
                input_device_id: self.input_device_id,
            },
        )
    }
}
