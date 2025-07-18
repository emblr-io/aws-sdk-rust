// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct ThreatActorIp {
    /// <p></p>
    pub ip_address: ::std::string::String,
    /// <p></p>
    pub user_agent: ::std::option::Option<::std::string::String>,
}
impl ThreatActorIp {
    /// <p></p>
    pub fn ip_address(&self) -> &str {
        use std::ops::Deref;
        self.ip_address.deref()
    }
    /// <p></p>
    pub fn user_agent(&self) -> ::std::option::Option<&str> {
        self.user_agent.as_deref()
    }
}
impl ::std::fmt::Debug for ThreatActorIp {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ThreatActorIp");
        formatter.field("ip_address", &"*** Sensitive Data Redacted ***");
        formatter.field("user_agent", &self.user_agent);
        formatter.finish()
    }
}
impl ThreatActorIp {
    /// Creates a new builder-style object to manufacture [`ThreatActorIp`](crate::types::ThreatActorIp).
    pub fn builder() -> crate::types::builders::ThreatActorIpBuilder {
        crate::types::builders::ThreatActorIpBuilder::default()
    }
}

/// A builder for [`ThreatActorIp`](crate::types::ThreatActorIp).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct ThreatActorIpBuilder {
    pub(crate) ip_address: ::std::option::Option<::std::string::String>,
    pub(crate) user_agent: ::std::option::Option<::std::string::String>,
}
impl ThreatActorIpBuilder {
    /// <p></p>
    /// This field is required.
    pub fn ip_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ip_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p></p>
    pub fn set_ip_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ip_address = input;
        self
    }
    /// <p></p>
    pub fn get_ip_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.ip_address
    }
    /// <p></p>
    pub fn user_agent(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_agent = ::std::option::Option::Some(input.into());
        self
    }
    /// <p></p>
    pub fn set_user_agent(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_agent = input;
        self
    }
    /// <p></p>
    pub fn get_user_agent(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_agent
    }
    /// Consumes the builder and constructs a [`ThreatActorIp`](crate::types::ThreatActorIp).
    /// This method will fail if any of the following fields are not set:
    /// - [`ip_address`](crate::types::builders::ThreatActorIpBuilder::ip_address)
    pub fn build(self) -> ::std::result::Result<crate::types::ThreatActorIp, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ThreatActorIp {
            ip_address: self.ip_address.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "ip_address",
                    "ip_address was not specified but it is required when building ThreatActorIp",
                )
            })?,
            user_agent: self.user_agent,
        })
    }
}
impl ::std::fmt::Debug for ThreatActorIpBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ThreatActorIpBuilder");
        formatter.field("ip_address", &"*** Sensitive Data Redacted ***");
        formatter.field("user_agent", &self.user_agent);
        formatter.finish()
    }
}
