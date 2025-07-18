// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeregisterDeviceOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeregisterDeviceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeregisterDeviceOutput {
    /// Creates a new builder-style object to manufacture [`DeregisterDeviceOutput`](crate::operation::deregister_device::DeregisterDeviceOutput).
    pub fn builder() -> crate::operation::deregister_device::builders::DeregisterDeviceOutputBuilder {
        crate::operation::deregister_device::builders::DeregisterDeviceOutputBuilder::default()
    }
}

/// A builder for [`DeregisterDeviceOutput`](crate::operation::deregister_device::DeregisterDeviceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeregisterDeviceOutputBuilder {
    _request_id: Option<String>,
}
impl DeregisterDeviceOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeregisterDeviceOutput`](crate::operation::deregister_device::DeregisterDeviceOutput).
    pub fn build(self) -> crate::operation::deregister_device::DeregisterDeviceOutput {
        crate::operation::deregister_device::DeregisterDeviceOutput {
            _request_id: self._request_id,
        }
    }
}
