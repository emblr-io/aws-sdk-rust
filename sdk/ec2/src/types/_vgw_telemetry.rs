// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes telemetry for a VPN tunnel.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VgwTelemetry {
    /// <p>The number of accepted routes.</p>
    pub accepted_route_count: ::std::option::Option<i32>,
    /// <p>The date and time of the last change in status. This field is updated when changes in IKE (Phase 1), IPSec (Phase 2), or BGP status are detected.</p>
    pub last_status_change: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Internet-routable IP address of the virtual private gateway's outside interface.</p>
    pub outside_ip_address: ::std::option::Option<::std::string::String>,
    /// <p>The status of the VPN tunnel.</p>
    pub status: ::std::option::Option<crate::types::TelemetryStatus>,
    /// <p>If an error occurs, a description of the error.</p>
    pub status_message: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the VPN tunnel endpoint certificate.</p>
    pub certificate_arn: ::std::option::Option<::std::string::String>,
}
impl VgwTelemetry {
    /// <p>The number of accepted routes.</p>
    pub fn accepted_route_count(&self) -> ::std::option::Option<i32> {
        self.accepted_route_count
    }
    /// <p>The date and time of the last change in status. This field is updated when changes in IKE (Phase 1), IPSec (Phase 2), or BGP status are detected.</p>
    pub fn last_status_change(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_status_change.as_ref()
    }
    /// <p>The Internet-routable IP address of the virtual private gateway's outside interface.</p>
    pub fn outside_ip_address(&self) -> ::std::option::Option<&str> {
        self.outside_ip_address.as_deref()
    }
    /// <p>The status of the VPN tunnel.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::TelemetryStatus> {
        self.status.as_ref()
    }
    /// <p>If an error occurs, a description of the error.</p>
    pub fn status_message(&self) -> ::std::option::Option<&str> {
        self.status_message.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the VPN tunnel endpoint certificate.</p>
    pub fn certificate_arn(&self) -> ::std::option::Option<&str> {
        self.certificate_arn.as_deref()
    }
}
impl VgwTelemetry {
    /// Creates a new builder-style object to manufacture [`VgwTelemetry`](crate::types::VgwTelemetry).
    pub fn builder() -> crate::types::builders::VgwTelemetryBuilder {
        crate::types::builders::VgwTelemetryBuilder::default()
    }
}

/// A builder for [`VgwTelemetry`](crate::types::VgwTelemetry).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VgwTelemetryBuilder {
    pub(crate) accepted_route_count: ::std::option::Option<i32>,
    pub(crate) last_status_change: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) outside_ip_address: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::TelemetryStatus>,
    pub(crate) status_message: ::std::option::Option<::std::string::String>,
    pub(crate) certificate_arn: ::std::option::Option<::std::string::String>,
}
impl VgwTelemetryBuilder {
    /// <p>The number of accepted routes.</p>
    pub fn accepted_route_count(mut self, input: i32) -> Self {
        self.accepted_route_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of accepted routes.</p>
    pub fn set_accepted_route_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.accepted_route_count = input;
        self
    }
    /// <p>The number of accepted routes.</p>
    pub fn get_accepted_route_count(&self) -> &::std::option::Option<i32> {
        &self.accepted_route_count
    }
    /// <p>The date and time of the last change in status. This field is updated when changes in IKE (Phase 1), IPSec (Phase 2), or BGP status are detected.</p>
    pub fn last_status_change(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_status_change = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time of the last change in status. This field is updated when changes in IKE (Phase 1), IPSec (Phase 2), or BGP status are detected.</p>
    pub fn set_last_status_change(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_status_change = input;
        self
    }
    /// <p>The date and time of the last change in status. This field is updated when changes in IKE (Phase 1), IPSec (Phase 2), or BGP status are detected.</p>
    pub fn get_last_status_change(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_status_change
    }
    /// <p>The Internet-routable IP address of the virtual private gateway's outside interface.</p>
    pub fn outside_ip_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.outside_ip_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Internet-routable IP address of the virtual private gateway's outside interface.</p>
    pub fn set_outside_ip_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.outside_ip_address = input;
        self
    }
    /// <p>The Internet-routable IP address of the virtual private gateway's outside interface.</p>
    pub fn get_outside_ip_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.outside_ip_address
    }
    /// <p>The status of the VPN tunnel.</p>
    pub fn status(mut self, input: crate::types::TelemetryStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the VPN tunnel.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::TelemetryStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the VPN tunnel.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::TelemetryStatus> {
        &self.status
    }
    /// <p>If an error occurs, a description of the error.</p>
    pub fn status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If an error occurs, a description of the error.</p>
    pub fn set_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_message = input;
        self
    }
    /// <p>If an error occurs, a description of the error.</p>
    pub fn get_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_message
    }
    /// <p>The Amazon Resource Name (ARN) of the VPN tunnel endpoint certificate.</p>
    pub fn certificate_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the VPN tunnel endpoint certificate.</p>
    pub fn set_certificate_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the VPN tunnel endpoint certificate.</p>
    pub fn get_certificate_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_arn
    }
    /// Consumes the builder and constructs a [`VgwTelemetry`](crate::types::VgwTelemetry).
    pub fn build(self) -> crate::types::VgwTelemetry {
        crate::types::VgwTelemetry {
            accepted_route_count: self.accepted_route_count,
            last_status_change: self.last_status_change,
            outside_ip_address: self.outside_ip_address,
            status: self.status,
            status_message: self.status_message,
            certificate_arn: self.certificate_arn,
        }
    }
}
