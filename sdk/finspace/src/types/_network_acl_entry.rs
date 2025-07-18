// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The network access control list (ACL) is an optional layer of security for your VPC that acts as a firewall for controlling traffic in and out of one or more subnets. The entry is a set of numbered ingress and egress rules that determine whether a packet should be allowed in or out of a subnet associated with the ACL. We process the entries in the ACL according to the rule numbers, in ascending order.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NetworkAclEntry {
    /// <p>The rule number for the entry. For example <i>100</i>. All the network ACL entries are processed in ascending order by rule number.</p>
    pub rule_number: i32,
    /// <p>The protocol number. A value of <i>-1</i> means all the protocols.</p>
    pub protocol: ::std::string::String,
    /// <p>Indicates whether to allow or deny the traffic that matches the rule.</p>
    pub rule_action: crate::types::RuleAction,
    /// <p>The range of ports the rule applies to.</p>
    pub port_range: ::std::option::Option<crate::types::PortRange>,
    /// <p>Defines the ICMP protocol that consists of the ICMP type and code.</p>
    pub icmp_type_code: ::std::option::Option<crate::types::IcmpTypeCode>,
    /// <p>The IPv4 network range to allow or deny, in CIDR notation. For example, <code>172.16.0.0/24</code>. We modify the specified CIDR block to its canonical form. For example, if you specify <code>100.68.0.18/18</code>, we modify it to <code>100.68.0.0/18</code>.</p>
    pub cidr_block: ::std::string::String,
}
impl NetworkAclEntry {
    /// <p>The rule number for the entry. For example <i>100</i>. All the network ACL entries are processed in ascending order by rule number.</p>
    pub fn rule_number(&self) -> i32 {
        self.rule_number
    }
    /// <p>The protocol number. A value of <i>-1</i> means all the protocols.</p>
    pub fn protocol(&self) -> &str {
        use std::ops::Deref;
        self.protocol.deref()
    }
    /// <p>Indicates whether to allow or deny the traffic that matches the rule.</p>
    pub fn rule_action(&self) -> &crate::types::RuleAction {
        &self.rule_action
    }
    /// <p>The range of ports the rule applies to.</p>
    pub fn port_range(&self) -> ::std::option::Option<&crate::types::PortRange> {
        self.port_range.as_ref()
    }
    /// <p>Defines the ICMP protocol that consists of the ICMP type and code.</p>
    pub fn icmp_type_code(&self) -> ::std::option::Option<&crate::types::IcmpTypeCode> {
        self.icmp_type_code.as_ref()
    }
    /// <p>The IPv4 network range to allow or deny, in CIDR notation. For example, <code>172.16.0.0/24</code>. We modify the specified CIDR block to its canonical form. For example, if you specify <code>100.68.0.18/18</code>, we modify it to <code>100.68.0.0/18</code>.</p>
    pub fn cidr_block(&self) -> &str {
        use std::ops::Deref;
        self.cidr_block.deref()
    }
}
impl NetworkAclEntry {
    /// Creates a new builder-style object to manufacture [`NetworkAclEntry`](crate::types::NetworkAclEntry).
    pub fn builder() -> crate::types::builders::NetworkAclEntryBuilder {
        crate::types::builders::NetworkAclEntryBuilder::default()
    }
}

/// A builder for [`NetworkAclEntry`](crate::types::NetworkAclEntry).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NetworkAclEntryBuilder {
    pub(crate) rule_number: ::std::option::Option<i32>,
    pub(crate) protocol: ::std::option::Option<::std::string::String>,
    pub(crate) rule_action: ::std::option::Option<crate::types::RuleAction>,
    pub(crate) port_range: ::std::option::Option<crate::types::PortRange>,
    pub(crate) icmp_type_code: ::std::option::Option<crate::types::IcmpTypeCode>,
    pub(crate) cidr_block: ::std::option::Option<::std::string::String>,
}
impl NetworkAclEntryBuilder {
    /// <p>The rule number for the entry. For example <i>100</i>. All the network ACL entries are processed in ascending order by rule number.</p>
    /// This field is required.
    pub fn rule_number(mut self, input: i32) -> Self {
        self.rule_number = ::std::option::Option::Some(input);
        self
    }
    /// <p>The rule number for the entry. For example <i>100</i>. All the network ACL entries are processed in ascending order by rule number.</p>
    pub fn set_rule_number(mut self, input: ::std::option::Option<i32>) -> Self {
        self.rule_number = input;
        self
    }
    /// <p>The rule number for the entry. For example <i>100</i>. All the network ACL entries are processed in ascending order by rule number.</p>
    pub fn get_rule_number(&self) -> &::std::option::Option<i32> {
        &self.rule_number
    }
    /// <p>The protocol number. A value of <i>-1</i> means all the protocols.</p>
    /// This field is required.
    pub fn protocol(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.protocol = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The protocol number. A value of <i>-1</i> means all the protocols.</p>
    pub fn set_protocol(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.protocol = input;
        self
    }
    /// <p>The protocol number. A value of <i>-1</i> means all the protocols.</p>
    pub fn get_protocol(&self) -> &::std::option::Option<::std::string::String> {
        &self.protocol
    }
    /// <p>Indicates whether to allow or deny the traffic that matches the rule.</p>
    /// This field is required.
    pub fn rule_action(mut self, input: crate::types::RuleAction) -> Self {
        self.rule_action = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether to allow or deny the traffic that matches the rule.</p>
    pub fn set_rule_action(mut self, input: ::std::option::Option<crate::types::RuleAction>) -> Self {
        self.rule_action = input;
        self
    }
    /// <p>Indicates whether to allow or deny the traffic that matches the rule.</p>
    pub fn get_rule_action(&self) -> &::std::option::Option<crate::types::RuleAction> {
        &self.rule_action
    }
    /// <p>The range of ports the rule applies to.</p>
    pub fn port_range(mut self, input: crate::types::PortRange) -> Self {
        self.port_range = ::std::option::Option::Some(input);
        self
    }
    /// <p>The range of ports the rule applies to.</p>
    pub fn set_port_range(mut self, input: ::std::option::Option<crate::types::PortRange>) -> Self {
        self.port_range = input;
        self
    }
    /// <p>The range of ports the rule applies to.</p>
    pub fn get_port_range(&self) -> &::std::option::Option<crate::types::PortRange> {
        &self.port_range
    }
    /// <p>Defines the ICMP protocol that consists of the ICMP type and code.</p>
    pub fn icmp_type_code(mut self, input: crate::types::IcmpTypeCode) -> Self {
        self.icmp_type_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>Defines the ICMP protocol that consists of the ICMP type and code.</p>
    pub fn set_icmp_type_code(mut self, input: ::std::option::Option<crate::types::IcmpTypeCode>) -> Self {
        self.icmp_type_code = input;
        self
    }
    /// <p>Defines the ICMP protocol that consists of the ICMP type and code.</p>
    pub fn get_icmp_type_code(&self) -> &::std::option::Option<crate::types::IcmpTypeCode> {
        &self.icmp_type_code
    }
    /// <p>The IPv4 network range to allow or deny, in CIDR notation. For example, <code>172.16.0.0/24</code>. We modify the specified CIDR block to its canonical form. For example, if you specify <code>100.68.0.18/18</code>, we modify it to <code>100.68.0.0/18</code>.</p>
    /// This field is required.
    pub fn cidr_block(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cidr_block = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IPv4 network range to allow or deny, in CIDR notation. For example, <code>172.16.0.0/24</code>. We modify the specified CIDR block to its canonical form. For example, if you specify <code>100.68.0.18/18</code>, we modify it to <code>100.68.0.0/18</code>.</p>
    pub fn set_cidr_block(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cidr_block = input;
        self
    }
    /// <p>The IPv4 network range to allow or deny, in CIDR notation. For example, <code>172.16.0.0/24</code>. We modify the specified CIDR block to its canonical form. For example, if you specify <code>100.68.0.18/18</code>, we modify it to <code>100.68.0.0/18</code>.</p>
    pub fn get_cidr_block(&self) -> &::std::option::Option<::std::string::String> {
        &self.cidr_block
    }
    /// Consumes the builder and constructs a [`NetworkAclEntry`](crate::types::NetworkAclEntry).
    /// This method will fail if any of the following fields are not set:
    /// - [`rule_number`](crate::types::builders::NetworkAclEntryBuilder::rule_number)
    /// - [`protocol`](crate::types::builders::NetworkAclEntryBuilder::protocol)
    /// - [`rule_action`](crate::types::builders::NetworkAclEntryBuilder::rule_action)
    /// - [`cidr_block`](crate::types::builders::NetworkAclEntryBuilder::cidr_block)
    pub fn build(self) -> ::std::result::Result<crate::types::NetworkAclEntry, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::NetworkAclEntry {
            rule_number: self.rule_number.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "rule_number",
                    "rule_number was not specified but it is required when building NetworkAclEntry",
                )
            })?,
            protocol: self.protocol.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "protocol",
                    "protocol was not specified but it is required when building NetworkAclEntry",
                )
            })?,
            rule_action: self.rule_action.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "rule_action",
                    "rule_action was not specified but it is required when building NetworkAclEntry",
                )
            })?,
            port_range: self.port_range,
            icmp_type_code: self.icmp_type_code,
            cidr_block: self.cidr_block.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "cidr_block",
                    "cidr_block was not specified but it is required when building NetworkAclEntry",
                )
            })?,
        })
    }
}
