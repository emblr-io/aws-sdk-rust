// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information on suspicious IP addresses identified as indicators of compromise. This indicator is derived from Amazon Web Services threat intelligence.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FlaggedIpAddressDetail {
    /// <p>IP address of the suspicious entity.</p>
    pub ip_address: ::std::option::Option<::std::string::String>,
    /// <p>Details the reason the IP address was flagged as suspicious.</p>
    pub reason: ::std::option::Option<crate::types::Reason>,
}
impl FlaggedIpAddressDetail {
    /// <p>IP address of the suspicious entity.</p>
    pub fn ip_address(&self) -> ::std::option::Option<&str> {
        self.ip_address.as_deref()
    }
    /// <p>Details the reason the IP address was flagged as suspicious.</p>
    pub fn reason(&self) -> ::std::option::Option<&crate::types::Reason> {
        self.reason.as_ref()
    }
}
impl FlaggedIpAddressDetail {
    /// Creates a new builder-style object to manufacture [`FlaggedIpAddressDetail`](crate::types::FlaggedIpAddressDetail).
    pub fn builder() -> crate::types::builders::FlaggedIpAddressDetailBuilder {
        crate::types::builders::FlaggedIpAddressDetailBuilder::default()
    }
}

/// A builder for [`FlaggedIpAddressDetail`](crate::types::FlaggedIpAddressDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FlaggedIpAddressDetailBuilder {
    pub(crate) ip_address: ::std::option::Option<::std::string::String>,
    pub(crate) reason: ::std::option::Option<crate::types::Reason>,
}
impl FlaggedIpAddressDetailBuilder {
    /// <p>IP address of the suspicious entity.</p>
    pub fn ip_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ip_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>IP address of the suspicious entity.</p>
    pub fn set_ip_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ip_address = input;
        self
    }
    /// <p>IP address of the suspicious entity.</p>
    pub fn get_ip_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.ip_address
    }
    /// <p>Details the reason the IP address was flagged as suspicious.</p>
    pub fn reason(mut self, input: crate::types::Reason) -> Self {
        self.reason = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details the reason the IP address was flagged as suspicious.</p>
    pub fn set_reason(mut self, input: ::std::option::Option<crate::types::Reason>) -> Self {
        self.reason = input;
        self
    }
    /// <p>Details the reason the IP address was flagged as suspicious.</p>
    pub fn get_reason(&self) -> &::std::option::Option<crate::types::Reason> {
        &self.reason
    }
    /// Consumes the builder and constructs a [`FlaggedIpAddressDetail`](crate::types::FlaggedIpAddressDetail).
    pub fn build(self) -> crate::types::FlaggedIpAddressDetail {
        crate::types::FlaggedIpAddressDetail {
            ip_address: self.ip_address,
            reason: self.reason,
        }
    }
}
