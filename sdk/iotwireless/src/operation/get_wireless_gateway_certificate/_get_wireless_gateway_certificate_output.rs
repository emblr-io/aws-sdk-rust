// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetWirelessGatewayCertificateOutput {
    /// <p>The ID of the certificate associated with the wireless gateway.</p>
    pub iot_certificate_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the certificate that is associated with the wireless gateway and used for the LoRaWANNetworkServer endpoint.</p>
    pub lo_ra_wan_network_server_certificate_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetWirelessGatewayCertificateOutput {
    /// <p>The ID of the certificate associated with the wireless gateway.</p>
    pub fn iot_certificate_id(&self) -> ::std::option::Option<&str> {
        self.iot_certificate_id.as_deref()
    }
    /// <p>The ID of the certificate that is associated with the wireless gateway and used for the LoRaWANNetworkServer endpoint.</p>
    pub fn lo_ra_wan_network_server_certificate_id(&self) -> ::std::option::Option<&str> {
        self.lo_ra_wan_network_server_certificate_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetWirelessGatewayCertificateOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetWirelessGatewayCertificateOutput {
    /// Creates a new builder-style object to manufacture [`GetWirelessGatewayCertificateOutput`](crate::operation::get_wireless_gateway_certificate::GetWirelessGatewayCertificateOutput).
    pub fn builder() -> crate::operation::get_wireless_gateway_certificate::builders::GetWirelessGatewayCertificateOutputBuilder {
        crate::operation::get_wireless_gateway_certificate::builders::GetWirelessGatewayCertificateOutputBuilder::default()
    }
}

/// A builder for [`GetWirelessGatewayCertificateOutput`](crate::operation::get_wireless_gateway_certificate::GetWirelessGatewayCertificateOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetWirelessGatewayCertificateOutputBuilder {
    pub(crate) iot_certificate_id: ::std::option::Option<::std::string::String>,
    pub(crate) lo_ra_wan_network_server_certificate_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetWirelessGatewayCertificateOutputBuilder {
    /// <p>The ID of the certificate associated with the wireless gateway.</p>
    pub fn iot_certificate_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.iot_certificate_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the certificate associated with the wireless gateway.</p>
    pub fn set_iot_certificate_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.iot_certificate_id = input;
        self
    }
    /// <p>The ID of the certificate associated with the wireless gateway.</p>
    pub fn get_iot_certificate_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.iot_certificate_id
    }
    /// <p>The ID of the certificate that is associated with the wireless gateway and used for the LoRaWANNetworkServer endpoint.</p>
    pub fn lo_ra_wan_network_server_certificate_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.lo_ra_wan_network_server_certificate_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the certificate that is associated with the wireless gateway and used for the LoRaWANNetworkServer endpoint.</p>
    pub fn set_lo_ra_wan_network_server_certificate_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.lo_ra_wan_network_server_certificate_id = input;
        self
    }
    /// <p>The ID of the certificate that is associated with the wireless gateway and used for the LoRaWANNetworkServer endpoint.</p>
    pub fn get_lo_ra_wan_network_server_certificate_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.lo_ra_wan_network_server_certificate_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetWirelessGatewayCertificateOutput`](crate::operation::get_wireless_gateway_certificate::GetWirelessGatewayCertificateOutput).
    pub fn build(self) -> crate::operation::get_wireless_gateway_certificate::GetWirelessGatewayCertificateOutput {
        crate::operation::get_wireless_gateway_certificate::GetWirelessGatewayCertificateOutput {
            iot_certificate_id: self.iot_certificate_id,
            lo_ra_wan_network_server_certificate_id: self.lo_ra_wan_network_server_certificate_id,
            _request_id: self._request_id,
        }
    }
}
