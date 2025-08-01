// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a security group rule.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AnalysisSecurityGroupRule {
    /// <p>The IPv4 address range, in CIDR notation.</p>
    pub cidr: ::std::option::Option<::std::string::String>,
    /// <p>The direction. The following are the possible values:</p>
    /// <ul>
    /// <li>
    /// <p>egress</p></li>
    /// <li>
    /// <p>ingress</p></li>
    /// </ul>
    pub direction: ::std::option::Option<::std::string::String>,
    /// <p>The security group ID.</p>
    pub security_group_id: ::std::option::Option<::std::string::String>,
    /// <p>The port range.</p>
    pub port_range: ::std::option::Option<crate::types::PortRange>,
    /// <p>The prefix list ID.</p>
    pub prefix_list_id: ::std::option::Option<::std::string::String>,
    /// <p>The protocol name.</p>
    pub protocol: ::std::option::Option<::std::string::String>,
}
impl AnalysisSecurityGroupRule {
    /// <p>The IPv4 address range, in CIDR notation.</p>
    pub fn cidr(&self) -> ::std::option::Option<&str> {
        self.cidr.as_deref()
    }
    /// <p>The direction. The following are the possible values:</p>
    /// <ul>
    /// <li>
    /// <p>egress</p></li>
    /// <li>
    /// <p>ingress</p></li>
    /// </ul>
    pub fn direction(&self) -> ::std::option::Option<&str> {
        self.direction.as_deref()
    }
    /// <p>The security group ID.</p>
    pub fn security_group_id(&self) -> ::std::option::Option<&str> {
        self.security_group_id.as_deref()
    }
    /// <p>The port range.</p>
    pub fn port_range(&self) -> ::std::option::Option<&crate::types::PortRange> {
        self.port_range.as_ref()
    }
    /// <p>The prefix list ID.</p>
    pub fn prefix_list_id(&self) -> ::std::option::Option<&str> {
        self.prefix_list_id.as_deref()
    }
    /// <p>The protocol name.</p>
    pub fn protocol(&self) -> ::std::option::Option<&str> {
        self.protocol.as_deref()
    }
}
impl AnalysisSecurityGroupRule {
    /// Creates a new builder-style object to manufacture [`AnalysisSecurityGroupRule`](crate::types::AnalysisSecurityGroupRule).
    pub fn builder() -> crate::types::builders::AnalysisSecurityGroupRuleBuilder {
        crate::types::builders::AnalysisSecurityGroupRuleBuilder::default()
    }
}

/// A builder for [`AnalysisSecurityGroupRule`](crate::types::AnalysisSecurityGroupRule).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AnalysisSecurityGroupRuleBuilder {
    pub(crate) cidr: ::std::option::Option<::std::string::String>,
    pub(crate) direction: ::std::option::Option<::std::string::String>,
    pub(crate) security_group_id: ::std::option::Option<::std::string::String>,
    pub(crate) port_range: ::std::option::Option<crate::types::PortRange>,
    pub(crate) prefix_list_id: ::std::option::Option<::std::string::String>,
    pub(crate) protocol: ::std::option::Option<::std::string::String>,
}
impl AnalysisSecurityGroupRuleBuilder {
    /// <p>The IPv4 address range, in CIDR notation.</p>
    pub fn cidr(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cidr = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IPv4 address range, in CIDR notation.</p>
    pub fn set_cidr(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cidr = input;
        self
    }
    /// <p>The IPv4 address range, in CIDR notation.</p>
    pub fn get_cidr(&self) -> &::std::option::Option<::std::string::String> {
        &self.cidr
    }
    /// <p>The direction. The following are the possible values:</p>
    /// <ul>
    /// <li>
    /// <p>egress</p></li>
    /// <li>
    /// <p>ingress</p></li>
    /// </ul>
    pub fn direction(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.direction = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The direction. The following are the possible values:</p>
    /// <ul>
    /// <li>
    /// <p>egress</p></li>
    /// <li>
    /// <p>ingress</p></li>
    /// </ul>
    pub fn set_direction(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.direction = input;
        self
    }
    /// <p>The direction. The following are the possible values:</p>
    /// <ul>
    /// <li>
    /// <p>egress</p></li>
    /// <li>
    /// <p>ingress</p></li>
    /// </ul>
    pub fn get_direction(&self) -> &::std::option::Option<::std::string::String> {
        &self.direction
    }
    /// <p>The security group ID.</p>
    pub fn security_group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.security_group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The security group ID.</p>
    pub fn set_security_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.security_group_id = input;
        self
    }
    /// <p>The security group ID.</p>
    pub fn get_security_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.security_group_id
    }
    /// <p>The port range.</p>
    pub fn port_range(mut self, input: crate::types::PortRange) -> Self {
        self.port_range = ::std::option::Option::Some(input);
        self
    }
    /// <p>The port range.</p>
    pub fn set_port_range(mut self, input: ::std::option::Option<crate::types::PortRange>) -> Self {
        self.port_range = input;
        self
    }
    /// <p>The port range.</p>
    pub fn get_port_range(&self) -> &::std::option::Option<crate::types::PortRange> {
        &self.port_range
    }
    /// <p>The prefix list ID.</p>
    pub fn prefix_list_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.prefix_list_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The prefix list ID.</p>
    pub fn set_prefix_list_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.prefix_list_id = input;
        self
    }
    /// <p>The prefix list ID.</p>
    pub fn get_prefix_list_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.prefix_list_id
    }
    /// <p>The protocol name.</p>
    pub fn protocol(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.protocol = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The protocol name.</p>
    pub fn set_protocol(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.protocol = input;
        self
    }
    /// <p>The protocol name.</p>
    pub fn get_protocol(&self) -> &::std::option::Option<::std::string::String> {
        &self.protocol
    }
    /// Consumes the builder and constructs a [`AnalysisSecurityGroupRule`](crate::types::AnalysisSecurityGroupRule).
    pub fn build(self) -> crate::types::AnalysisSecurityGroupRule {
        crate::types::AnalysisSecurityGroupRule {
            cidr: self.cidr,
            direction: self.direction,
            security_group_id: self.security_group_id,
            port_range: self.port_range,
            prefix_list_id: self.prefix_list_id,
            protocol: self.protocol,
        }
    }
}
