// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details related to why an IPAM pool CIDR failed to be provisioned.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IpamPoolCidrFailureReason {
    /// <p>An error code related to why an IPAM pool CIDR failed to be provisioned.</p>
    pub code: ::std::option::Option<crate::types::IpamPoolCidrFailureCode>,
    /// <p>A message related to why an IPAM pool CIDR failed to be provisioned.</p>
    pub message: ::std::option::Option<::std::string::String>,
}
impl IpamPoolCidrFailureReason {
    /// <p>An error code related to why an IPAM pool CIDR failed to be provisioned.</p>
    pub fn code(&self) -> ::std::option::Option<&crate::types::IpamPoolCidrFailureCode> {
        self.code.as_ref()
    }
    /// <p>A message related to why an IPAM pool CIDR failed to be provisioned.</p>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl IpamPoolCidrFailureReason {
    /// Creates a new builder-style object to manufacture [`IpamPoolCidrFailureReason`](crate::types::IpamPoolCidrFailureReason).
    pub fn builder() -> crate::types::builders::IpamPoolCidrFailureReasonBuilder {
        crate::types::builders::IpamPoolCidrFailureReasonBuilder::default()
    }
}

/// A builder for [`IpamPoolCidrFailureReason`](crate::types::IpamPoolCidrFailureReason).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IpamPoolCidrFailureReasonBuilder {
    pub(crate) code: ::std::option::Option<crate::types::IpamPoolCidrFailureCode>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
}
impl IpamPoolCidrFailureReasonBuilder {
    /// <p>An error code related to why an IPAM pool CIDR failed to be provisioned.</p>
    pub fn code(mut self, input: crate::types::IpamPoolCidrFailureCode) -> Self {
        self.code = ::std::option::Option::Some(input);
        self
    }
    /// <p>An error code related to why an IPAM pool CIDR failed to be provisioned.</p>
    pub fn set_code(mut self, input: ::std::option::Option<crate::types::IpamPoolCidrFailureCode>) -> Self {
        self.code = input;
        self
    }
    /// <p>An error code related to why an IPAM pool CIDR failed to be provisioned.</p>
    pub fn get_code(&self) -> &::std::option::Option<crate::types::IpamPoolCidrFailureCode> {
        &self.code
    }
    /// <p>A message related to why an IPAM pool CIDR failed to be provisioned.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A message related to why an IPAM pool CIDR failed to be provisioned.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>A message related to why an IPAM pool CIDR failed to be provisioned.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Consumes the builder and constructs a [`IpamPoolCidrFailureReason`](crate::types::IpamPoolCidrFailureReason).
    pub fn build(self) -> crate::types::IpamPoolCidrFailureReason {
        crate::types::IpamPoolCidrFailureReason {
            code: self.code,
            message: self.message,
        }
    }
}
