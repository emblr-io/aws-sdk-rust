// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateDeviceInstanceOutput {
    /// <p>An object that contains information about your device instance.</p>
    pub device_instance: ::std::option::Option<crate::types::DeviceInstance>,
    _request_id: Option<String>,
}
impl UpdateDeviceInstanceOutput {
    /// <p>An object that contains information about your device instance.</p>
    pub fn device_instance(&self) -> ::std::option::Option<&crate::types::DeviceInstance> {
        self.device_instance.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateDeviceInstanceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateDeviceInstanceOutput {
    /// Creates a new builder-style object to manufacture [`UpdateDeviceInstanceOutput`](crate::operation::update_device_instance::UpdateDeviceInstanceOutput).
    pub fn builder() -> crate::operation::update_device_instance::builders::UpdateDeviceInstanceOutputBuilder {
        crate::operation::update_device_instance::builders::UpdateDeviceInstanceOutputBuilder::default()
    }
}

/// A builder for [`UpdateDeviceInstanceOutput`](crate::operation::update_device_instance::UpdateDeviceInstanceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateDeviceInstanceOutputBuilder {
    pub(crate) device_instance: ::std::option::Option<crate::types::DeviceInstance>,
    _request_id: Option<String>,
}
impl UpdateDeviceInstanceOutputBuilder {
    /// <p>An object that contains information about your device instance.</p>
    pub fn device_instance(mut self, input: crate::types::DeviceInstance) -> Self {
        self.device_instance = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains information about your device instance.</p>
    pub fn set_device_instance(mut self, input: ::std::option::Option<crate::types::DeviceInstance>) -> Self {
        self.device_instance = input;
        self
    }
    /// <p>An object that contains information about your device instance.</p>
    pub fn get_device_instance(&self) -> &::std::option::Option<crate::types::DeviceInstance> {
        &self.device_instance
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateDeviceInstanceOutput`](crate::operation::update_device_instance::UpdateDeviceInstanceOutput).
    pub fn build(self) -> crate::operation::update_device_instance::UpdateDeviceInstanceOutput {
        crate::operation::update_device_instance::UpdateDeviceInstanceOutput {
            device_instance: self.device_instance,
            _request_id: self._request_id,
        }
    }
}
