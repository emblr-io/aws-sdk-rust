// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the result of an update device pool request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateDevicePoolOutput {
    /// <p>The device pool you just updated.</p>
    pub device_pool: ::std::option::Option<crate::types::DevicePool>,
    _request_id: Option<String>,
}
impl UpdateDevicePoolOutput {
    /// <p>The device pool you just updated.</p>
    pub fn device_pool(&self) -> ::std::option::Option<&crate::types::DevicePool> {
        self.device_pool.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateDevicePoolOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateDevicePoolOutput {
    /// Creates a new builder-style object to manufacture [`UpdateDevicePoolOutput`](crate::operation::update_device_pool::UpdateDevicePoolOutput).
    pub fn builder() -> crate::operation::update_device_pool::builders::UpdateDevicePoolOutputBuilder {
        crate::operation::update_device_pool::builders::UpdateDevicePoolOutputBuilder::default()
    }
}

/// A builder for [`UpdateDevicePoolOutput`](crate::operation::update_device_pool::UpdateDevicePoolOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateDevicePoolOutputBuilder {
    pub(crate) device_pool: ::std::option::Option<crate::types::DevicePool>,
    _request_id: Option<String>,
}
impl UpdateDevicePoolOutputBuilder {
    /// <p>The device pool you just updated.</p>
    pub fn device_pool(mut self, input: crate::types::DevicePool) -> Self {
        self.device_pool = ::std::option::Option::Some(input);
        self
    }
    /// <p>The device pool you just updated.</p>
    pub fn set_device_pool(mut self, input: ::std::option::Option<crate::types::DevicePool>) -> Self {
        self.device_pool = input;
        self
    }
    /// <p>The device pool you just updated.</p>
    pub fn get_device_pool(&self) -> &::std::option::Option<crate::types::DevicePool> {
        &self.device_pool
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateDevicePoolOutput`](crate::operation::update_device_pool::UpdateDevicePoolOutput).
    pub fn build(self) -> crate::operation::update_device_pool::UpdateDevicePoolOutput {
        crate::operation::update_device_pool::UpdateDevicePoolOutput {
            device_pool: self.device_pool,
            _request_id: self._request_id,
        }
    }
}
