// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An IPAM discovered account. A discovered account is an Amazon Web Services account that is monitored under a resource discovery. If you have integrated IPAM with Amazon Web Services Organizations, all accounts in the organization are discovered accounts.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IpamDiscoveredAccount {
    /// <p>The account ID.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services Region that the account information is returned from. An account can be discovered in multiple regions and will have a separate discovered account for each Region.</p>
    pub discovery_region: ::std::option::Option<::std::string::String>,
    /// <p>The resource discovery failure reason.</p>
    pub failure_reason: ::std::option::Option<crate::types::IpamDiscoveryFailureReason>,
    /// <p>The last attempted resource discovery time.</p>
    pub last_attempted_discovery_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The last successful resource discovery time.</p>
    pub last_successful_discovery_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The ID of an Organizational Unit in Amazon Web Services Organizations.</p>
    pub organizational_unit_id: ::std::option::Option<::std::string::String>,
}
impl IpamDiscoveredAccount {
    /// <p>The account ID.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>The Amazon Web Services Region that the account information is returned from. An account can be discovered in multiple regions and will have a separate discovered account for each Region.</p>
    pub fn discovery_region(&self) -> ::std::option::Option<&str> {
        self.discovery_region.as_deref()
    }
    /// <p>The resource discovery failure reason.</p>
    pub fn failure_reason(&self) -> ::std::option::Option<&crate::types::IpamDiscoveryFailureReason> {
        self.failure_reason.as_ref()
    }
    /// <p>The last attempted resource discovery time.</p>
    pub fn last_attempted_discovery_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_attempted_discovery_time.as_ref()
    }
    /// <p>The last successful resource discovery time.</p>
    pub fn last_successful_discovery_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_successful_discovery_time.as_ref()
    }
    /// <p>The ID of an Organizational Unit in Amazon Web Services Organizations.</p>
    pub fn organizational_unit_id(&self) -> ::std::option::Option<&str> {
        self.organizational_unit_id.as_deref()
    }
}
impl IpamDiscoveredAccount {
    /// Creates a new builder-style object to manufacture [`IpamDiscoveredAccount`](crate::types::IpamDiscoveredAccount).
    pub fn builder() -> crate::types::builders::IpamDiscoveredAccountBuilder {
        crate::types::builders::IpamDiscoveredAccountBuilder::default()
    }
}

/// A builder for [`IpamDiscoveredAccount`](crate::types::IpamDiscoveredAccount).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IpamDiscoveredAccountBuilder {
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) discovery_region: ::std::option::Option<::std::string::String>,
    pub(crate) failure_reason: ::std::option::Option<crate::types::IpamDiscoveryFailureReason>,
    pub(crate) last_attempted_discovery_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_successful_discovery_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) organizational_unit_id: ::std::option::Option<::std::string::String>,
}
impl IpamDiscoveredAccountBuilder {
    /// <p>The account ID.</p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The account ID.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The account ID.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>The Amazon Web Services Region that the account information is returned from. An account can be discovered in multiple regions and will have a separate discovered account for each Region.</p>
    pub fn discovery_region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.discovery_region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services Region that the account information is returned from. An account can be discovered in multiple regions and will have a separate discovered account for each Region.</p>
    pub fn set_discovery_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.discovery_region = input;
        self
    }
    /// <p>The Amazon Web Services Region that the account information is returned from. An account can be discovered in multiple regions and will have a separate discovered account for each Region.</p>
    pub fn get_discovery_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.discovery_region
    }
    /// <p>The resource discovery failure reason.</p>
    pub fn failure_reason(mut self, input: crate::types::IpamDiscoveryFailureReason) -> Self {
        self.failure_reason = ::std::option::Option::Some(input);
        self
    }
    /// <p>The resource discovery failure reason.</p>
    pub fn set_failure_reason(mut self, input: ::std::option::Option<crate::types::IpamDiscoveryFailureReason>) -> Self {
        self.failure_reason = input;
        self
    }
    /// <p>The resource discovery failure reason.</p>
    pub fn get_failure_reason(&self) -> &::std::option::Option<crate::types::IpamDiscoveryFailureReason> {
        &self.failure_reason
    }
    /// <p>The last attempted resource discovery time.</p>
    pub fn last_attempted_discovery_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_attempted_discovery_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The last attempted resource discovery time.</p>
    pub fn set_last_attempted_discovery_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_attempted_discovery_time = input;
        self
    }
    /// <p>The last attempted resource discovery time.</p>
    pub fn get_last_attempted_discovery_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_attempted_discovery_time
    }
    /// <p>The last successful resource discovery time.</p>
    pub fn last_successful_discovery_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_successful_discovery_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The last successful resource discovery time.</p>
    pub fn set_last_successful_discovery_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_successful_discovery_time = input;
        self
    }
    /// <p>The last successful resource discovery time.</p>
    pub fn get_last_successful_discovery_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_successful_discovery_time
    }
    /// <p>The ID of an Organizational Unit in Amazon Web Services Organizations.</p>
    pub fn organizational_unit_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.organizational_unit_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of an Organizational Unit in Amazon Web Services Organizations.</p>
    pub fn set_organizational_unit_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.organizational_unit_id = input;
        self
    }
    /// <p>The ID of an Organizational Unit in Amazon Web Services Organizations.</p>
    pub fn get_organizational_unit_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.organizational_unit_id
    }
    /// Consumes the builder and constructs a [`IpamDiscoveredAccount`](crate::types::IpamDiscoveredAccount).
    pub fn build(self) -> crate::types::IpamDiscoveredAccount {
        crate::types::IpamDiscoveredAccount {
            account_id: self.account_id,
            discovery_region: self.discovery_region,
            failure_reason: self.failure_reason,
            last_attempted_discovery_time: self.last_attempted_discovery_time,
            last_successful_discovery_time: self.last_successful_discovery_time,
            organizational_unit_id: self.organizational_unit_id,
        }
    }
}
