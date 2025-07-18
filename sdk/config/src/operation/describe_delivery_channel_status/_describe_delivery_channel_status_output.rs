// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The output for the <code>DescribeDeliveryChannelStatus</code> action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeDeliveryChannelStatusOutput {
    /// <p>A list that contains the status of a specified delivery channel.</p>
    pub delivery_channels_status: ::std::option::Option<::std::vec::Vec<crate::types::DeliveryChannelStatus>>,
    _request_id: Option<String>,
}
impl DescribeDeliveryChannelStatusOutput {
    /// <p>A list that contains the status of a specified delivery channel.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.delivery_channels_status.is_none()`.
    pub fn delivery_channels_status(&self) -> &[crate::types::DeliveryChannelStatus] {
        self.delivery_channels_status.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for DescribeDeliveryChannelStatusOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeDeliveryChannelStatusOutput {
    /// Creates a new builder-style object to manufacture [`DescribeDeliveryChannelStatusOutput`](crate::operation::describe_delivery_channel_status::DescribeDeliveryChannelStatusOutput).
    pub fn builder() -> crate::operation::describe_delivery_channel_status::builders::DescribeDeliveryChannelStatusOutputBuilder {
        crate::operation::describe_delivery_channel_status::builders::DescribeDeliveryChannelStatusOutputBuilder::default()
    }
}

/// A builder for [`DescribeDeliveryChannelStatusOutput`](crate::operation::describe_delivery_channel_status::DescribeDeliveryChannelStatusOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeDeliveryChannelStatusOutputBuilder {
    pub(crate) delivery_channels_status: ::std::option::Option<::std::vec::Vec<crate::types::DeliveryChannelStatus>>,
    _request_id: Option<String>,
}
impl DescribeDeliveryChannelStatusOutputBuilder {
    /// Appends an item to `delivery_channels_status`.
    ///
    /// To override the contents of this collection use [`set_delivery_channels_status`](Self::set_delivery_channels_status).
    ///
    /// <p>A list that contains the status of a specified delivery channel.</p>
    pub fn delivery_channels_status(mut self, input: crate::types::DeliveryChannelStatus) -> Self {
        let mut v = self.delivery_channels_status.unwrap_or_default();
        v.push(input);
        self.delivery_channels_status = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list that contains the status of a specified delivery channel.</p>
    pub fn set_delivery_channels_status(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DeliveryChannelStatus>>) -> Self {
        self.delivery_channels_status = input;
        self
    }
    /// <p>A list that contains the status of a specified delivery channel.</p>
    pub fn get_delivery_channels_status(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DeliveryChannelStatus>> {
        &self.delivery_channels_status
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeDeliveryChannelStatusOutput`](crate::operation::describe_delivery_channel_status::DescribeDeliveryChannelStatusOutput).
    pub fn build(self) -> crate::operation::describe_delivery_channel_status::DescribeDeliveryChannelStatusOutput {
        crate::operation::describe_delivery_channel_status::DescribeDeliveryChannelStatusOutput {
            delivery_channels_status: self.delivery_channels_status,
            _request_id: self._request_id,
        }
    }
}
