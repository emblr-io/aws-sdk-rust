// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartBulkAssociateWirelessDeviceWithMulticastGroupOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for StartBulkAssociateWirelessDeviceWithMulticastGroupOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartBulkAssociateWirelessDeviceWithMulticastGroupOutput {
    /// Creates a new builder-style object to manufacture [`StartBulkAssociateWirelessDeviceWithMulticastGroupOutput`](crate::operation::start_bulk_associate_wireless_device_with_multicast_group::StartBulkAssociateWirelessDeviceWithMulticastGroupOutput).
    pub fn builder() -> crate::operation::start_bulk_associate_wireless_device_with_multicast_group::builders::StartBulkAssociateWirelessDeviceWithMulticastGroupOutputBuilder{
        crate::operation::start_bulk_associate_wireless_device_with_multicast_group::builders::StartBulkAssociateWirelessDeviceWithMulticastGroupOutputBuilder::default()
    }
}

/// A builder for [`StartBulkAssociateWirelessDeviceWithMulticastGroupOutput`](crate::operation::start_bulk_associate_wireless_device_with_multicast_group::StartBulkAssociateWirelessDeviceWithMulticastGroupOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartBulkAssociateWirelessDeviceWithMulticastGroupOutputBuilder {
    _request_id: Option<String>,
}
impl StartBulkAssociateWirelessDeviceWithMulticastGroupOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartBulkAssociateWirelessDeviceWithMulticastGroupOutput`](crate::operation::start_bulk_associate_wireless_device_with_multicast_group::StartBulkAssociateWirelessDeviceWithMulticastGroupOutput).
    pub fn build(
        self,
    ) -> crate::operation::start_bulk_associate_wireless_device_with_multicast_group::StartBulkAssociateWirelessDeviceWithMulticastGroupOutput {
        crate::operation::start_bulk_associate_wireless_device_with_multicast_group::StartBulkAssociateWirelessDeviceWithMulticastGroupOutput {
            _request_id: self._request_id,
        }
    }
}
