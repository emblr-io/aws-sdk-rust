// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListDeviceInstancesOutput {
    /// <p>An object that contains information about your device instances.</p>
    pub device_instances: ::std::option::Option<::std::vec::Vec<crate::types::DeviceInstance>>,
    /// <p>An identifier that can be used in the next call to this operation to return the next set of items in the list.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListDeviceInstancesOutput {
    /// <p>An object that contains information about your device instances.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.device_instances.is_none()`.
    pub fn device_instances(&self) -> &[crate::types::DeviceInstance] {
        self.device_instances.as_deref().unwrap_or_default()
    }
    /// <p>An identifier that can be used in the next call to this operation to return the next set of items in the list.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListDeviceInstancesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListDeviceInstancesOutput {
    /// Creates a new builder-style object to manufacture [`ListDeviceInstancesOutput`](crate::operation::list_device_instances::ListDeviceInstancesOutput).
    pub fn builder() -> crate::operation::list_device_instances::builders::ListDeviceInstancesOutputBuilder {
        crate::operation::list_device_instances::builders::ListDeviceInstancesOutputBuilder::default()
    }
}

/// A builder for [`ListDeviceInstancesOutput`](crate::operation::list_device_instances::ListDeviceInstancesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListDeviceInstancesOutputBuilder {
    pub(crate) device_instances: ::std::option::Option<::std::vec::Vec<crate::types::DeviceInstance>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListDeviceInstancesOutputBuilder {
    /// Appends an item to `device_instances`.
    ///
    /// To override the contents of this collection use [`set_device_instances`](Self::set_device_instances).
    ///
    /// <p>An object that contains information about your device instances.</p>
    pub fn device_instances(mut self, input: crate::types::DeviceInstance) -> Self {
        let mut v = self.device_instances.unwrap_or_default();
        v.push(input);
        self.device_instances = ::std::option::Option::Some(v);
        self
    }
    /// <p>An object that contains information about your device instances.</p>
    pub fn set_device_instances(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DeviceInstance>>) -> Self {
        self.device_instances = input;
        self
    }
    /// <p>An object that contains information about your device instances.</p>
    pub fn get_device_instances(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DeviceInstance>> {
        &self.device_instances
    }
    /// <p>An identifier that can be used in the next call to this operation to return the next set of items in the list.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An identifier that can be used in the next call to this operation to return the next set of items in the list.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>An identifier that can be used in the next call to this operation to return the next set of items in the list.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListDeviceInstancesOutput`](crate::operation::list_device_instances::ListDeviceInstancesOutput).
    pub fn build(self) -> crate::operation::list_device_instances::ListDeviceInstancesOutput {
        crate::operation::list_device_instances::ListDeviceInstancesOutput {
            device_instances: self.device_instances,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
