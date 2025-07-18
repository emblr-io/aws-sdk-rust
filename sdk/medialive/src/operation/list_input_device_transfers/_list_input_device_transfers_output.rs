// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Placeholder documentation for ListInputDeviceTransfersResponse
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListInputDeviceTransfersOutput {
    /// The list of devices that you are transferring or are being transferred to you.
    pub input_device_transfers: ::std::option::Option<::std::vec::Vec<crate::types::TransferringInputDeviceSummary>>,
    /// A token to get additional list results.
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListInputDeviceTransfersOutput {
    /// The list of devices that you are transferring or are being transferred to you.
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.input_device_transfers.is_none()`.
    pub fn input_device_transfers(&self) -> &[crate::types::TransferringInputDeviceSummary] {
        self.input_device_transfers.as_deref().unwrap_or_default()
    }
    /// A token to get additional list results.
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListInputDeviceTransfersOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListInputDeviceTransfersOutput {
    /// Creates a new builder-style object to manufacture [`ListInputDeviceTransfersOutput`](crate::operation::list_input_device_transfers::ListInputDeviceTransfersOutput).
    pub fn builder() -> crate::operation::list_input_device_transfers::builders::ListInputDeviceTransfersOutputBuilder {
        crate::operation::list_input_device_transfers::builders::ListInputDeviceTransfersOutputBuilder::default()
    }
}

/// A builder for [`ListInputDeviceTransfersOutput`](crate::operation::list_input_device_transfers::ListInputDeviceTransfersOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListInputDeviceTransfersOutputBuilder {
    pub(crate) input_device_transfers: ::std::option::Option<::std::vec::Vec<crate::types::TransferringInputDeviceSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListInputDeviceTransfersOutputBuilder {
    /// Appends an item to `input_device_transfers`.
    ///
    /// To override the contents of this collection use [`set_input_device_transfers`](Self::set_input_device_transfers).
    ///
    /// The list of devices that you are transferring or are being transferred to you.
    pub fn input_device_transfers(mut self, input: crate::types::TransferringInputDeviceSummary) -> Self {
        let mut v = self.input_device_transfers.unwrap_or_default();
        v.push(input);
        self.input_device_transfers = ::std::option::Option::Some(v);
        self
    }
    /// The list of devices that you are transferring or are being transferred to you.
    pub fn set_input_device_transfers(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TransferringInputDeviceSummary>>) -> Self {
        self.input_device_transfers = input;
        self
    }
    /// The list of devices that you are transferring or are being transferred to you.
    pub fn get_input_device_transfers(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TransferringInputDeviceSummary>> {
        &self.input_device_transfers
    }
    /// A token to get additional list results.
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// A token to get additional list results.
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// A token to get additional list results.
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
    /// Consumes the builder and constructs a [`ListInputDeviceTransfersOutput`](crate::operation::list_input_device_transfers::ListInputDeviceTransfersOutput).
    pub fn build(self) -> crate::operation::list_input_device_transfers::ListInputDeviceTransfersOutput {
        crate::operation::list_input_device_transfers::ListInputDeviceTransfersOutput {
            input_device_transfers: self.input_device_transfers,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
