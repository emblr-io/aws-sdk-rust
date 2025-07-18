// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDevicePositionHistoryOutput {
    /// <p>Contains the position history details for the requested device.</p>
    pub device_positions: ::std::vec::Vec<crate::types::DevicePosition>,
    /// <p>A pagination token indicating there are additional pages available. You can use the token in a following request to fetch the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetDevicePositionHistoryOutput {
    /// <p>Contains the position history details for the requested device.</p>
    pub fn device_positions(&self) -> &[crate::types::DevicePosition] {
        use std::ops::Deref;
        self.device_positions.deref()
    }
    /// <p>A pagination token indicating there are additional pages available. You can use the token in a following request to fetch the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetDevicePositionHistoryOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetDevicePositionHistoryOutput {
    /// Creates a new builder-style object to manufacture [`GetDevicePositionHistoryOutput`](crate::operation::get_device_position_history::GetDevicePositionHistoryOutput).
    pub fn builder() -> crate::operation::get_device_position_history::builders::GetDevicePositionHistoryOutputBuilder {
        crate::operation::get_device_position_history::builders::GetDevicePositionHistoryOutputBuilder::default()
    }
}

/// A builder for [`GetDevicePositionHistoryOutput`](crate::operation::get_device_position_history::GetDevicePositionHistoryOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDevicePositionHistoryOutputBuilder {
    pub(crate) device_positions: ::std::option::Option<::std::vec::Vec<crate::types::DevicePosition>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetDevicePositionHistoryOutputBuilder {
    /// Appends an item to `device_positions`.
    ///
    /// To override the contents of this collection use [`set_device_positions`](Self::set_device_positions).
    ///
    /// <p>Contains the position history details for the requested device.</p>
    pub fn device_positions(mut self, input: crate::types::DevicePosition) -> Self {
        let mut v = self.device_positions.unwrap_or_default();
        v.push(input);
        self.device_positions = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains the position history details for the requested device.</p>
    pub fn set_device_positions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DevicePosition>>) -> Self {
        self.device_positions = input;
        self
    }
    /// <p>Contains the position history details for the requested device.</p>
    pub fn get_device_positions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DevicePosition>> {
        &self.device_positions
    }
    /// <p>A pagination token indicating there are additional pages available. You can use the token in a following request to fetch the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A pagination token indicating there are additional pages available. You can use the token in a following request to fetch the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A pagination token indicating there are additional pages available. You can use the token in a following request to fetch the next set of results.</p>
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
    /// Consumes the builder and constructs a [`GetDevicePositionHistoryOutput`](crate::operation::get_device_position_history::GetDevicePositionHistoryOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`device_positions`](crate::operation::get_device_position_history::builders::GetDevicePositionHistoryOutputBuilder::device_positions)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_device_position_history::GetDevicePositionHistoryOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_device_position_history::GetDevicePositionHistoryOutput {
            device_positions: self.device_positions.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "device_positions",
                    "device_positions was not specified but it is required when building GetDevicePositionHistoryOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
