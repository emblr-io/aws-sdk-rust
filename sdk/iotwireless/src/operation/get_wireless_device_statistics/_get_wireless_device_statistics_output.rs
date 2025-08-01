// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetWirelessDeviceStatisticsOutput {
    /// <p>The ID of the wireless device.</p>
    pub wireless_device_id: ::std::option::Option<::std::string::String>,
    /// <p>The date and time when the most recent uplink was received.</p><note>
    /// <p>This value is only valid for 3 months.</p>
    /// </note>
    pub last_uplink_received_at: ::std::option::Option<::std::string::String>,
    /// <p>Information about the wireless device's operations.</p>
    pub lo_ra_wan: ::std::option::Option<crate::types::LoRaWanDeviceMetadata>,
    /// <p>MetaData for Sidewalk device.</p>
    pub sidewalk: ::std::option::Option<crate::types::SidewalkDeviceMetadata>,
    _request_id: Option<String>,
}
impl GetWirelessDeviceStatisticsOutput {
    /// <p>The ID of the wireless device.</p>
    pub fn wireless_device_id(&self) -> ::std::option::Option<&str> {
        self.wireless_device_id.as_deref()
    }
    /// <p>The date and time when the most recent uplink was received.</p><note>
    /// <p>This value is only valid for 3 months.</p>
    /// </note>
    pub fn last_uplink_received_at(&self) -> ::std::option::Option<&str> {
        self.last_uplink_received_at.as_deref()
    }
    /// <p>Information about the wireless device's operations.</p>
    pub fn lo_ra_wan(&self) -> ::std::option::Option<&crate::types::LoRaWanDeviceMetadata> {
        self.lo_ra_wan.as_ref()
    }
    /// <p>MetaData for Sidewalk device.</p>
    pub fn sidewalk(&self) -> ::std::option::Option<&crate::types::SidewalkDeviceMetadata> {
        self.sidewalk.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetWirelessDeviceStatisticsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetWirelessDeviceStatisticsOutput {
    /// Creates a new builder-style object to manufacture [`GetWirelessDeviceStatisticsOutput`](crate::operation::get_wireless_device_statistics::GetWirelessDeviceStatisticsOutput).
    pub fn builder() -> crate::operation::get_wireless_device_statistics::builders::GetWirelessDeviceStatisticsOutputBuilder {
        crate::operation::get_wireless_device_statistics::builders::GetWirelessDeviceStatisticsOutputBuilder::default()
    }
}

/// A builder for [`GetWirelessDeviceStatisticsOutput`](crate::operation::get_wireless_device_statistics::GetWirelessDeviceStatisticsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetWirelessDeviceStatisticsOutputBuilder {
    pub(crate) wireless_device_id: ::std::option::Option<::std::string::String>,
    pub(crate) last_uplink_received_at: ::std::option::Option<::std::string::String>,
    pub(crate) lo_ra_wan: ::std::option::Option<crate::types::LoRaWanDeviceMetadata>,
    pub(crate) sidewalk: ::std::option::Option<crate::types::SidewalkDeviceMetadata>,
    _request_id: Option<String>,
}
impl GetWirelessDeviceStatisticsOutputBuilder {
    /// <p>The ID of the wireless device.</p>
    pub fn wireless_device_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.wireless_device_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the wireless device.</p>
    pub fn set_wireless_device_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.wireless_device_id = input;
        self
    }
    /// <p>The ID of the wireless device.</p>
    pub fn get_wireless_device_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.wireless_device_id
    }
    /// <p>The date and time when the most recent uplink was received.</p><note>
    /// <p>This value is only valid for 3 months.</p>
    /// </note>
    pub fn last_uplink_received_at(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_uplink_received_at = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The date and time when the most recent uplink was received.</p><note>
    /// <p>This value is only valid for 3 months.</p>
    /// </note>
    pub fn set_last_uplink_received_at(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_uplink_received_at = input;
        self
    }
    /// <p>The date and time when the most recent uplink was received.</p><note>
    /// <p>This value is only valid for 3 months.</p>
    /// </note>
    pub fn get_last_uplink_received_at(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_uplink_received_at
    }
    /// <p>Information about the wireless device's operations.</p>
    pub fn lo_ra_wan(mut self, input: crate::types::LoRaWanDeviceMetadata) -> Self {
        self.lo_ra_wan = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the wireless device's operations.</p>
    pub fn set_lo_ra_wan(mut self, input: ::std::option::Option<crate::types::LoRaWanDeviceMetadata>) -> Self {
        self.lo_ra_wan = input;
        self
    }
    /// <p>Information about the wireless device's operations.</p>
    pub fn get_lo_ra_wan(&self) -> &::std::option::Option<crate::types::LoRaWanDeviceMetadata> {
        &self.lo_ra_wan
    }
    /// <p>MetaData for Sidewalk device.</p>
    pub fn sidewalk(mut self, input: crate::types::SidewalkDeviceMetadata) -> Self {
        self.sidewalk = ::std::option::Option::Some(input);
        self
    }
    /// <p>MetaData for Sidewalk device.</p>
    pub fn set_sidewalk(mut self, input: ::std::option::Option<crate::types::SidewalkDeviceMetadata>) -> Self {
        self.sidewalk = input;
        self
    }
    /// <p>MetaData for Sidewalk device.</p>
    pub fn get_sidewalk(&self) -> &::std::option::Option<crate::types::SidewalkDeviceMetadata> {
        &self.sidewalk
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetWirelessDeviceStatisticsOutput`](crate::operation::get_wireless_device_statistics::GetWirelessDeviceStatisticsOutput).
    pub fn build(self) -> crate::operation::get_wireless_device_statistics::GetWirelessDeviceStatisticsOutput {
        crate::operation::get_wireless_device_statistics::GetWirelessDeviceStatisticsOutput {
            wireless_device_id: self.wireless_device_id,
            last_uplink_received_at: self.last_uplink_received_at,
            lo_ra_wan: self.lo_ra_wan,
            sidewalk: self.sidewalk,
            _request_id: self._request_id,
        }
    }
}
