// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains variables that you can use to override default Suricata settings in your firewall policy.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PolicyVariables {
    /// <p>The IPv4 or IPv6 addresses in CIDR notation to use for the Suricata <code>HOME_NET</code> variable. If your firewall uses an inspection VPC, you might want to override the <code>HOME_NET</code> variable with the CIDRs of your home networks. If you don't override <code>HOME_NET</code> with your own CIDRs, Network Firewall by default uses the CIDR of your inspection VPC.</p>
    pub rule_variables: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::IpSet>>,
}
impl PolicyVariables {
    /// <p>The IPv4 or IPv6 addresses in CIDR notation to use for the Suricata <code>HOME_NET</code> variable. If your firewall uses an inspection VPC, you might want to override the <code>HOME_NET</code> variable with the CIDRs of your home networks. If you don't override <code>HOME_NET</code> with your own CIDRs, Network Firewall by default uses the CIDR of your inspection VPC.</p>
    pub fn rule_variables(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::IpSet>> {
        self.rule_variables.as_ref()
    }
}
impl PolicyVariables {
    /// Creates a new builder-style object to manufacture [`PolicyVariables`](crate::types::PolicyVariables).
    pub fn builder() -> crate::types::builders::PolicyVariablesBuilder {
        crate::types::builders::PolicyVariablesBuilder::default()
    }
}

/// A builder for [`PolicyVariables`](crate::types::PolicyVariables).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PolicyVariablesBuilder {
    pub(crate) rule_variables: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::IpSet>>,
}
impl PolicyVariablesBuilder {
    /// Adds a key-value pair to `rule_variables`.
    ///
    /// To override the contents of this collection use [`set_rule_variables`](Self::set_rule_variables).
    ///
    /// <p>The IPv4 or IPv6 addresses in CIDR notation to use for the Suricata <code>HOME_NET</code> variable. If your firewall uses an inspection VPC, you might want to override the <code>HOME_NET</code> variable with the CIDRs of your home networks. If you don't override <code>HOME_NET</code> with your own CIDRs, Network Firewall by default uses the CIDR of your inspection VPC.</p>
    pub fn rule_variables(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::IpSet) -> Self {
        let mut hash_map = self.rule_variables.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.rule_variables = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The IPv4 or IPv6 addresses in CIDR notation to use for the Suricata <code>HOME_NET</code> variable. If your firewall uses an inspection VPC, you might want to override the <code>HOME_NET</code> variable with the CIDRs of your home networks. If you don't override <code>HOME_NET</code> with your own CIDRs, Network Firewall by default uses the CIDR of your inspection VPC.</p>
    pub fn set_rule_variables(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::IpSet>>,
    ) -> Self {
        self.rule_variables = input;
        self
    }
    /// <p>The IPv4 or IPv6 addresses in CIDR notation to use for the Suricata <code>HOME_NET</code> variable. If your firewall uses an inspection VPC, you might want to override the <code>HOME_NET</code> variable with the CIDRs of your home networks. If you don't override <code>HOME_NET</code> with your own CIDRs, Network Firewall by default uses the CIDR of your inspection VPC.</p>
    pub fn get_rule_variables(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::IpSet>> {
        &self.rule_variables
    }
    /// Consumes the builder and constructs a [`PolicyVariables`](crate::types::PolicyVariables).
    pub fn build(self) -> crate::types::PolicyVariables {
        crate::types::PolicyVariables {
            rule_variables: self.rule_variables,
        }
    }
}
